import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

const VERSION_PATTERN = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9a-z.-]+))?(?:\+[0-9a-z.-]+)?$/i;

// Minimal semver parsing: an optional "v" prefix, missing minor/patch as 0, and
// pre-release identifiers. Returns null for anything else (ranges, "latest", ...).
function parseVersion(value) {
  const match = VERSION_PATTERN.exec(String(value ?? "").trim());
  if (!match) return null;
  return {
    core: [match[1], match[2] || 0, match[3] || 0].map(Number),
    pre: match[4] ? match[4].split(".") : []
  };
}

function compareIdentifiers(a, b) {
  const aNum = /^\d+$/.test(a);
  const bNum = /^\d+$/.test(b);
  if (aNum && bNum) return Number(a) - Number(b);
  if (aNum !== bNum) return aNum ? -1 : 1; // numeric identifiers sort before alphanumeric
  return a < b ? -1 : a > b ? 1 : 0;
}

// Semver precedence: a pre-release sorts below its release (2.0.0-beta.1 < 2.0.0).
function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a.core[i] !== b.core[i]) return a.core[i] - b.core[i];
  }
  if (!a.pre.length || !b.pre.length) return b.pre.length - a.pre.length;
  for (let i = 0; i < Math.min(a.pre.length, b.pre.length); i++) {
    const diff = compareIdentifiers(a.pre[i], b.pre[i]);
    if (diff !== 0) return diff;
  }
  return a.pre.length - b.pre.length;
}

export class ComponentPolicy {
  constructor({ allowlist = null, denylist = [], minVersions = {} } = {}) {
    this.allowlist = allowlist ? new Set(allowlist) : null;
    this.denylist = new Set(denylist);
    this.minVersions = minVersions;
    for (const [name, version] of Object.entries(minVersions)) {
      if (!parseVersion(version)) {
        throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, "minVersions entry is not a valid version", { name, version });
      }
    }
  }

  evaluate(pkg) {
    if (this.allowlist && !this.allowlist.has(pkg.name)) {
      return { allowed: false, reason: "not_in_allowlist" };
    }
    if (this.denylist.has(pkg.name)) {
      return { allowed: false, reason: "in_denylist" };
    }
    const minVersion = Object.hasOwn(this.minVersions, pkg.name) ? this.minVersions[pkg.name] : null;
    if (minVersion) {
      const current = parseVersion(pkg.version);
      if (!current) {
        return { allowed: false, reason: "unparsable_version", required: minVersion };
      }
      if (compareVersions(current, parseVersion(minVersion)) < 0) {
        return { allowed: false, reason: "below_minimum_version", required: minVersion };
      }
    }
    return { allowed: true, reason: "allowed" };
  }
}
