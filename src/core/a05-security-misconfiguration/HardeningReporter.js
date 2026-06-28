export class HardeningReporter {
  constructor(configManager) {
    this.configManager = configManager;
  }

  generate() {
    const findings = this.configManager.detectUnsafeSettings();
    return findings.map((finding) => ({
      ...finding,
      recommendation: `Fix ${finding.id} to align with secure defaults.`
    }));
  }
}