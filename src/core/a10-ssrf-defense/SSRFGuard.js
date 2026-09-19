import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

// CIDR ranges that must never be reachable via an outbound request: private,
// loopback, link-local (includes cloud metadata at 169.254.169.254), and reserved space.
const IPV4_BLOCKED_RANGES = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4]
];

function ipv4ToLong(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    value = (value << 8) | n;
  }
  return value >>> 0;
}

function isBlockedIPv4(ip) {
  const target = ipv4ToLong(ip);
  if (target === null) return true; // unparsable address: fail closed
  return IPV4_BLOCKED_RANGES.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (target & mask) === (ipv4ToLong(base) & mask);
  });
}

// Expands any valid IPv6 literal (including "::" shorthand and an embedded
// trailing IPv4 address, e.g. "::ffff:169.254.169.254") to 8 numeric groups.
function expandIPv6Groups(hostname) {
  let address = hostname;
  const ipv4Suffix = address.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (ipv4Suffix) {
    const long = ipv4ToLong(ipv4Suffix[1]);
    if (long === null) return null;
    const hex = long.toString(16).padStart(8, "0");
    address = address.slice(0, -ipv4Suffix[1].length) + `${hex.slice(0, 4)}:${hex.slice(4)}`;
  }

  const hasCollapse = address.includes("::");
  const [head, tail] = hasCollapse ? address.split("::") : [address, null];
  const headGroups = head ? head.split(":").filter(Boolean) : [];
  const tailGroups = tail ? tail.split(":").filter(Boolean) : [];

  let groups;
  if (!hasCollapse) {
    if (headGroups.length !== 8) return null;
    groups = headGroups;
  } else {
    const missing = 8 - headGroups.length - tailGroups.length;
    if (missing < 0) return null;
    groups = [...headGroups, ...Array(missing).fill("0"), ...tailGroups];
  }

  const numeric = groups.map((g) => parseInt(g, 16));
  return numeric.some((g) => Number.isNaN(g)) ? null : numeric;
}

function isBlockedIPv6(hostname) {
  const groups = expandIPv6Groups(hostname);
  if (!groups) return true; // unparsable address: fail closed

  const isZero = (list) => list.every((g) => g === 0);

  if (isZero(groups)) return true; // "::" unspecified
  if (isZero(groups.slice(0, 7)) && groups[7] === 1) return true; // "::1" loopback
  if ((groups[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((groups[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local

  // IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96) embed an IPv4 target.
  const isMapped = isZero(groups.slice(0, 5)) && groups[5] === 0xffff;
  const isNat64 = groups[0] === 0x0064 && groups[1] === 0xff9b && isZero(groups.slice(2, 6));
  if (isMapped || isNat64) {
    const embedded = ((groups[6] << 16) | groups[7]) >>> 0;
    const embeddedIp = [24, 16, 8, 0].map((shift) => (embedded >>> shift) & 0xff).join(".");
    return isBlockedIPv4(embeddedIp);
  }

  return false;
}

function stripBrackets(hostname) {
  return hostname.replace(/^\[/, "").replace(/\]$/, "");
}

// Returns true/false for a literal IP address, or null when hostname is a DNS name.
// Implemented without node:net's isIP() so this module stays safe to bundle for browsers.
function isBlockedIPLiteral(hostname) {
  const bare = stripBrackets(hostname);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)) {
    return isBlockedIPv4(bare);
  }
  if (bare.includes(":")) {
    return isBlockedIPv6(bare);
  }
  return null;
}

export class SSRFGuard {
  /**
   * @param {{allowProtocols?: string[], maxRedirectHops?: number, resolveHost?: (hostname: string) => Promise<string[]>}} [options]
   */
  constructor({ allowProtocols = ["https:", "http:"], maxRedirectHops = 3, resolveHost = null } = {}) {
    this.allowProtocols = new Set(allowProtocols);
    this.maxRedirectHops = maxRedirectHops;
    this.resolveHost = resolveHost || defaultResolveHost;
  }

  isPrivateHost(hostname) {
    const bare = stripBrackets(hostname).toLowerCase();
    if (["localhost", "::1"].includes(bare) || bare.endsWith(".local")) {
      return true;
    }
    const literalResult = isBlockedIPLiteral(bare);
    return literalResult === null ? false : literalResult;
  }

  /**
   * Synchronous, literal-value validation: protocol allowlist and hostname/IP
   * pattern checks. Does NOT resolve DNS, so it cannot detect DNS rebinding
   * (a public hostname whose A/AAAA record points at a private address).
   * Prefer `assertResolvedSafe()` before making the actual outbound request.
   */
  validateUrl(input) {
    const url = new URL(input);
    if (!this.allowProtocols.has(url.protocol)) {
      throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Protocol not allowed", { protocol: url.protocol });
    }
    if (this.isPrivateHost(url.hostname)) {
      throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Private or loopback target blocked", { host: url.hostname });
    }
    return url;
  }

  /**
   * Resolves the hostname (unless it is already a literal IP) and validates
   * every returned address, closing the DNS-rebinding gap in `validateUrl()`.
   * Must be called immediately before each connection attempt, including
   * every redirect hop, to keep the resolve-then-check window minimal.
   */
  async assertResolvedSafe(input) {
    const url = this.validateUrl(input);
    const bareHost = stripBrackets(url.hostname);

    if (isBlockedIPLiteral(bareHost) === null) {
      let addresses;
      try {
        addresses = await this.resolveHost(bareHost);
      } catch (error) {
        throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Host could not be resolved", {
          host: bareHost,
          cause: String(error)
        });
      }

      const blockedAddress = addresses.find((address) => isBlockedIPLiteral(address) !== false);
      if (blockedAddress) {
        throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Resolved address is private, loopback, or reserved", {
          host: bareHost,
          address: blockedAddress
        });
      }
    }

    return url;
  }

  validateRedirectChain(chain) {
    if (chain.length > this.maxRedirectHops) {
      throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Redirect hop limit exceeded", {
        max: this.maxRedirectHops
      });
    }
    chain.forEach((url) => this.validateUrl(url));
    return true;
  }
}

async function defaultResolveHost(hostname) {
  const lookupFn = await getNodeDnsLookup();
  if (!lookupFn) return []; // no DNS resolution available in this runtime (e.g. browser bundle)
  const records = await lookupFn(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

// Loaded lazily (and only under Node) so this module remains safe to bundle for browsers,
// where "node:dns" does not exist.
let dnsLookupPromise = null;
function getNodeDnsLookup() {
  if (!dnsLookupPromise) {
    dnsLookupPromise =
      typeof process !== "undefined" && process?.versions?.node
        ? import("node:dns/promises")
            .then((dns) => dns.lookup)
            .catch(() => null)
        : Promise.resolve(null);
  }
  return dnsLookupPromise;
}