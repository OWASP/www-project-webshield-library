import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

const EFFECTS = new Set(["allow", "deny"]);

export class ACLManager {
  constructor() {
    // action -> (resource -> effect). Nested maps instead of an "action:resource"
    // string key, so a ":" inside an action or resource name can't collide with another rule.
    this.policies = new Map();
  }

  /**
   * Sets (or replaces) the rule for this exact resource/action pair. Use "*" as
   * the resource for a rule that covers every resource of that action.
   */
  setPolicy(resource, action, effect) {
    if (!EFFECTS.has(effect)) {
      throw new SecurityError(SecurityErrorCode.INVALID_INPUT, 'ACL effect must be "allow" or "deny"', { effect });
    }
    const byResource = this.policies.get(action) || new Map();
    byResource.set(resource, effect);
    this.policies.set(action, byResource);
  }

  /**
   * Deny overrides allow: a deny on either the direct or the wildcard rule wins,
   * whichever is more specific.
   */
  evaluate(resource, action) {
    const byResource = this.policies.get(action);
    const direct = byResource?.get(resource);
    const wildcard = byResource?.get("*");
    const effect = direct === "deny" || wildcard === "deny" ? "deny" : direct || wildcard || "neutral";
    return {
      effect,
      allowed: effect === "allow"
    };
  }
}
