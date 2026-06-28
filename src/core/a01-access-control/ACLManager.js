export class ACLManager {
  constructor() {
    this.policies = new Map();
  }

  /**
   * Deny overrides allow for deterministic conflict resolution.
   */
  setPolicy(resource, action, effect) {
    const key = `${action}:${resource}`;
    this.policies.set(key, effect);
  }

  evaluate(resource, action) {
    const direct = this.policies.get(`${action}:${resource}`);
    const wildcard = this.policies.get(`${action}:*`);
    const effect = direct || wildcard || "neutral";
    return {
      effect,
      allowed: effect === "allow"
    };
  }
}