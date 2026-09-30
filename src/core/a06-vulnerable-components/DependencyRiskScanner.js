import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

const SEVERITY_ORDER = ["low", "medium", "high", "critical"];
// Vocabulary used by common scanners (npm audit: "info"/"moderate") mapped onto ours.
const SEVERITY_ALIASES = { info: "low", informational: "low", moderate: "medium" };

function severityIndex(severity) {
  const value = String(severity ?? "").trim().toLowerCase();
  return SEVERITY_ORDER.indexOf(SEVERITY_ALIASES[value] || value);
}

export class DependencyRiskScanner {
  /**
   * @param {{scan: () => Promise<Array<{name:string,severity:string,fixedVersion?:string,currentVersion?:string}>>}} provider
   */
  constructor(provider) {
    this.provider = provider;
  }

  async scan() {
    const findings = await this.provider.scan();
    return findings.map((item) => ({
      package: item.name,
      severity: item.severity,
      fixedVersion: item.fixedVersion || null,
      currentVersion: item.currentVersion || null
    }));
  }

  // Severities are matched case-insensitively with scanner aliases (e.g. npm's
  // "moderate"); a finding whose severity is still unrecognized blocks the gate.
  async passesPolicy(threshold = "high") {
    const thresholdIdx = severityIndex(threshold);
    if (thresholdIdx === -1) {
      throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "Unknown severity threshold", { threshold });
    }
    const results = await this.scan();
    const blocked = results.filter((r) => {
      const idx = severityIndex(r.severity);
      return idx === -1 || idx >= thresholdIdx;
    });
    return { pass: blocked.length === 0, blocked, results };
  }
}
