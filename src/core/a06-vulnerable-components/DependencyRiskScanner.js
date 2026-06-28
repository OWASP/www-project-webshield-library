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

  async passesPolicy(threshold = "high") {
    const severities = ["low", "medium", "high", "critical"];
    const thresholdIdx = severities.indexOf(threshold);
    const results = await this.scan();
    const blocked = results.filter((r) => severities.indexOf(r.severity) >= thresholdIdx);
    return { pass: blocked.length === 0, blocked, results };
  }
}