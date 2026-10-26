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

  const embeddedIPv4 = (high, low) => [high >>> 8, high & 0xff, low >>> 8, low & 0xff].join(".");

  // ::/96 covers "::" (unspecified), "::1" (loopback) and deprecated IPv4-compatible "::a.b.c.d".
  if (isZero(groups.slice(0, 6))) return true;
  if ((groups[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((groups[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((groups[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 site-local (deprecated)
  if ((groups[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  if (groups[0] === 0x0064 && groups[1] === 0xff9b && groups[2] === 0x0001) return true; // 64:ff9b:1::/48 local-use NAT64

  // IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96) embed an IPv4 target.
  const isMapped = isZero(groups.slice(0, 5)) && groups[5] === 0xffff;
  const isNat64 = groups[0] === 0x0064 && groups[1] === 0xff9b && isZero(groups.slice(2, 6));
  if (isMapped || isNat64) {
    return isBlockedIPv4(embeddedIPv4(groups[6], groups[7]));
  }
  // 6to4 (2002::/16) carries its IPv4 address in the next 32 bits.
  if (groups[0] === 0x2002) {
    return isBlockedIPv4(embeddedIPv4(groups[1], groups[2]));
  }

  return false;
}

// A loop rather than /\.+$/: that regex backtracks quadratically on long runs of
// dots that aren't at the end ("a....b"), and hostnames come from untrusted URLs.
function stripTrailingDots(value) {
  let end = value.length;
  while (end > 0 && value[end - 1] === ".") end--;
  return value.slice(0, end);
}

function stripBrackets(hostname) {
  return hostname.replace(/^\[/, "").replace(/\]$/, "");
}

function normalizeProtocol(protocol) {
  if (typeof protocol !== "string") return "";
  const trimmed = protocol.trim().toLowerCase();
  return trimmed.endsWith(":") ? trimmed : `${trimmed}:`;
}

/**
 * Normalizes a hostname: trims, lowercases, strips brackets and trailing dots,
 * and canonicalizes IDN/IDNA representations via the standard URL parser.
 *
 * @param {string} hostname
 * @returns {string}
 */
export function normalizeHostname(hostname) {
  if (typeof hostname !== "string") return "";
  const bare = stripTrailingDots(stripBrackets(hostname.trim()).toLowerCase());
  if (!bare) return "";
  try {
    const parsed = new URL(`https://${bare}`).hostname;
    return stripTrailingDots(stripBrackets(parsed).toLowerCase());
  } catch {
    return bare;
  }
}

function normalizePattern(pattern) {
  if (typeof pattern !== "string") return null;
  const trimmed = pattern.trim().toLowerCase();
  if (!trimmed) return null;

  if (trimmed.startsWith("*.")) {
    const rawSuffix = trimmed.slice(2);
    const suffix = stripTrailingDots(stripBrackets(rawSuffix));
    if (!suffix) return null;
    let normalizedSuffix = suffix;
    try {
      normalizedSuffix = stripTrailingDots(stripBrackets(new URL(`https://${suffix}`).hostname.toLowerCase()));
    } catch {
      // fallback
    }
    return `*.${normalizedSuffix}`;
  }

  const exact = stripTrailingDots(stripBrackets(trimmed));
  if (!exact) return null;
  let normalizedExact = exact;
  try {
    normalizedExact = stripTrailingDots(stripBrackets(new URL(`https://${exact}`).hostname.toLowerCase()));
  } catch {
    // fallback
  }
  return normalizedExact;
}

function matchesPattern(normalizedHost, normalizedPattern) {
  if (!normalizedHost || !normalizedPattern) return false;

  if (normalizedPattern.startsWith("*.")) {
    const suffix = normalizedPattern.slice(2);
    if (!normalizedHost.endsWith(`.${suffix}`)) {
      return false;
    }
    const prefix = normalizedHost.slice(0, -(suffix.length + 1));
    return prefix.length > 0 && !prefix.includes(".");
  }

  return normalizedHost === normalizedPattern;
}

/**
 * Checks whether a hostname matches an allowlist of exact and wildcard host patterns.
 *
 * @param {string} hostname
 * @param {string[] | Iterable<string>} allowHosts
 * @returns {boolean}
 */
export function matchHostAllowlist(hostname, allowHosts) {
  if (!allowHosts) return false;
  const list = Array.isArray(allowHosts) ? allowHosts : Array.from(allowHosts);
  if (list.length === 0) return false;

  const normalizedHost = normalizeHostname(hostname);
  if (!normalizedHost) return false;

  for (const pattern of list) {
    const normalizedPattern = normalizePattern(pattern);
    if (matchesPattern(normalizedHost, normalizedPattern)) {
      return true;
    }
  }
  return false;
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
   * @param {{allowHosts?: string[] | Iterable<string>, allowProtocols?: string[] | Iterable<string>, maxRedirectHops?: number, resolveHost?: (hostname: string) => Promise<string[]>}} [options]
   */
  constructor({ allowHosts, allowProtocols, maxRedirectHops = 3, resolveHost = null } = {}) {
    this.allowHosts = allowHosts !== undefined ? Array.from(allowHosts) : null;
    const defaultProtocols = allowHosts !== undefined ? ["https:"] : ["https:", "http:"];
    const protocols = allowProtocols !== undefined ? allowProtocols : defaultProtocols;
    this.allowProtocols = new Set(Array.from(protocols).map(normalizeProtocol));
    this.maxRedirectHops = maxRedirectHops;
    this.resolveHost = resolveHost || defaultResolveHost;
  }

  isHostAllowed(hostname) {
    if (this.allowHosts === null) {
      return true;
    }
    return matchHostAllowlist(hostname, this.allowHosts);
  }

  isPrivateHost(hostname) {
    // A trailing dot ("localhost.") is the same fully-qualified name to a resolver.
    const bare = stripTrailingDots(stripBrackets(hostname).toLowerCase());
    // RFC 6761: "localhost" and every "*.localhost" name are loopback.
    if (bare === "localhost" || bare.endsWith(".localhost") || bare.endsWith(".local")) {
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
    const url = input instanceof URL ? input : new URL(input);
    if (!this.allowProtocols.has(url.protocol)) {
      throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Protocol not allowed", { protocol: url.protocol });
    }
    if (this.allowHosts !== null && !this.isHostAllowed(url.hostname)) {
      throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Host not allowed", { host: url.hostname });
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
    const bareHost = stripTrailingDots(stripBrackets(url.hostname));

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

      // Only the built-in resolver may answer "no DNS API here" (null, in browsers);
      // an empty answer from any resolver means the host is unverified, so fail closed.
      if (addresses === null && this.resolveHost === defaultResolveHost) {
        return url;
      }
      if (!Array.isArray(addresses) || addresses.length === 0) {
        throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Host could not be resolved", { host: bareHost });
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

  /**
   * Returns a `dns.lookup`-compatible function that rejects private/reserved
   * addresses at socket-connect time. Because the socket connects to exactly the
   * address validated here, this closes the resolve-then-connect (TOCTOU) window
   * that `assertResolvedSafe()` alone cannot. Use it with an undici dispatcher:
   * `new Agent({ connect: { lookup: guard.createSafeLookup() } })`.
   * Accepts optional `pinned` address or host-to-address mapping to pin the connection
   * to the exact validated IP while preserving TLS SNI and hostname verification.
   */
  createSafeLookup(pinned = null) {
    return (hostname, options, callback) => {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      const opts = typeof options === "number" ? { family: options } : options || {};

      const resolveAddresses = async () => {
        if (this.allowHosts !== null && !this.isHostAllowed(hostname)) {
          throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Host not allowed", { host: hostname });
        }

        let pinnedTarget = null;
        if (typeof pinned === "string") {
          pinnedTarget = [pinned];
        } else if (pinned && typeof pinned === "object") {
          const val = pinned instanceof Map ? pinned.get(hostname) : pinned[hostname];
          if (val) {
            pinnedTarget = Array.isArray(val) ? val : [val];
          }
        }

        if (pinnedTarget) {
          return pinnedTarget;
        }
        return this.resolveHost(hostname);
      };

      const resolved = Promise.resolve()
        .then(() => resolveAddresses())
        .then((addresses) => {
          const records = (Array.isArray(addresses) ? addresses : [])
            .map((address) => ({ address, family: address.includes(":") ? 6 : 4 }))
            .filter((record) => !opts.family || record.family === opts.family);
          if (records.length === 0) {
            throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Host could not be resolved", { host: hostname });
          }
          const blocked = records.find((record) => isBlockedIPLiteral(record.address) !== false);
          if (blocked) {
            throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Resolved address is private, loopback, or reserved", {
              host: hostname,
              address: blocked.address
            });
          }
          return records;
        });

      resolved.then(
        (records) => (opts.all ? callback(null, records) : callback(null, records[0].address, records[0].family)),
        (error) => callback(error)
      );
    };
  }

  /**
   * Returns a lookup function pinned to the exact validated IP address(es).
   * @param {string | Record<string, string | string[]> | Map<string, string | string[]>} hostnameOrMap
   * @param {string} [ip]
   */
  createPinnedLookup(hostnameOrMap, ip) {
    if (typeof hostnameOrMap === "string" && ip) {
      return this.createSafeLookup({ [hostnameOrMap]: ip });
    }
    return this.createSafeLookup(hostnameOrMap);
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

/**
 * Synchronously checks whether a URL is permitted according to SSRF policies.
 * Parses the URL with the standard URL parser, normalizes hostname case, trailing dots,
 * and IDN/IDNA representations, and performs safe exact hostname matching (e.g. `*.domain.com`).
 * Enforces HTTPS by default; permits other schemes only through explicit opt-in.
 * Blocks private, loopback, link-local, and reserved IP/host targets.
 *
 * @param {string | URL} url - The URL to validate.
 * @param {{allowHosts?: string[] | Iterable<string>, allowProtocols?: string[] | Iterable<string>, allowSchemes?: string[] | Iterable<string>} | string[] | Iterable<string> | SSRFGuard} [options]
 * @returns {boolean} True if the URL is allowed, false otherwise.
 */
export function isAllowedUrl(url, options = {}) {
  try {
    if (!url || (typeof url !== "string" && !(url instanceof URL))) {
      return false;
    }
    const parsed = url instanceof URL ? url : new URL(url);

    let opts = options;
    if (Array.isArray(options) || options instanceof Set) {
      opts = { allowHosts: options };
    } else if (options instanceof SSRFGuard) {
      opts = {
        allowHosts: options.allowHosts,
        allowProtocols: options.allowProtocols
      };
    }

    const rawProtocols = opts.allowProtocols || opts.allowSchemes;
    const allowedProtocols = rawProtocols
      ? new Set(Array.from(rawProtocols).map(normalizeProtocol))
      : new Set(["https:"]);

    if (!allowedProtocols.has(parsed.protocol)) {
      return false;
    }

    const guard = new SSRFGuard();
    if (guard.isPrivateHost(parsed.hostname)) {
      return false;
    }

    if (opts.allowHosts !== undefined) {
      const allowHostsList = Array.isArray(opts.allowHosts) ? opts.allowHosts : Array.from(opts.allowHosts);
      if (allowHostsList.length === 0) {
        return false;
      }
      return matchHostAllowlist(parsed.hostname, allowHostsList);
    }

    return true;
  } catch {
    return false;
  }
}

async function defaultResolveHost(hostname) {
  const lookupFn = await getNodeDnsLookup();
  if (!lookupFn) return null; // no DNS API in this runtime (browser bundle): see assertResolvedSafe()
  const records = await lookupFn(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

// Under Node a failed import must fail closed (reject) rather than skip the DNS check.
// The try block also tells bundlers (esbuild) that this import may be unresolvable,
// which keeps browser builds from failing on "node:dns/promises".
async function loadNodeDnsLookup() {
  try {
    const dns = await import("node:dns/promises");
    return dns.lookup;
  } catch (error) {
    throw new Error(`node:dns/promises could not be loaded: ${error}`);
  }
}

// Loaded lazily (and only under Node) so this module remains safe to bundle for browsers,
// where "node:dns" does not exist.
let dnsLookupPromise = null;
function getNodeDnsLookup() {
  if (!dnsLookupPromise) {
    dnsLookupPromise =
      typeof process !== "undefined" && process?.versions?.node ? loadNodeDnsLookup() : Promise.resolve(null);
  }
  return dnsLookupPromise;
}