export class ACLManager {
    policies: Map<any, any>;
    /**
     * Sets (or replaces) the rule for this exact resource/action pair. Use "*" as
     * the resource for a rule that covers every resource of that action.
     */
    setPolicy(resource: any, action: any, effect: any): void;
    /**
     * Deny overrides allow: a deny on either the direct or the wildcard rule wins,
     * whichever is more specific.
     */
    evaluate(resource: any, action: any): {
        effect: any;
        allowed: boolean;
    };
}
