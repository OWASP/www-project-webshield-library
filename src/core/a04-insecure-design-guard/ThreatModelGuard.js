export class ThreatModelGuard {
  constructor({ transitions = {}, abuseRules = [] } = {}) {
    this.transitions = transitions;
    this.abuseRules = abuseRules;
  }

  canTransition(from, to) {
    // Own keys only: "constructor", "__proto__" etc. must not resolve to Object.prototype members.
    const allowed = Object.hasOwn(this.transitions, from) ? this.transitions[from] : [];
    return Array.isArray(allowed) && allowed.includes(to);
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