export class ThreatModelGuard {
  constructor({ transitions = {}, abuseRules = [] } = {}) {
    this.transitions = transitions;
    this.abuseRules = abuseRules;
  }

  canTransition(from, to) {
    const allowed = this.transitions[from] || [];
    return allowed.includes(to);
  }

  validateTransition(from, to) {
    return {
      valid: this.canTransition(from, to),
      reason: this.canTransition(from, to) ? "allowed" : "forbidden_transition"
    };
  }

  evaluateAbuseCase(context) {
    const violations = this.abuseRules
      .filter((rule) => !rule.check(context))
      .map((rule) => ({ id: rule.id, message: rule.message }));
    return {
      valid: violations.length === 0,
      violations
    };
  }
}