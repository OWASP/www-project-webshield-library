export class ComponentPolicy {
  constructor({ allowlist = null, denylist = [], minVersions = {} } = {}) {
    this.allowlist = allowlist ? new Set(allowlist) : null;
    this.denylist = new Set(denylist);
    this.minVersions = minVersions;
  }

  evaluate(pkg) {
    if (this.allowlist && !this.allowlist.has(pkg.name)) {
      return { allowed: false, reason: "not_in_allowlist" };
    }
    if (this.denylist.has(pkg.name)) {
      return { allowed: false, reason: "in_denylist" };
    }
    const minVersion = this.minVersions[pkg.name];
    if (minVersion && String(pkg.version).localeCompare(minVersion, undefined, { numeric: true }) < 0) {
      return { allowed: false, reason: "below_minimum_version", required: minVersion };
    }
    return { allowed: true, reason: "allowed" };
  }
}