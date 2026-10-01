export class ThreatModelGuard {
    constructor({ transitions, abuseRules }?: {
        transitions?: {};
        abuseRules?: any[];
    });
    transitions: {};
    abuseRules: any[];
    canTransition(from: any, to: any): boolean;
    validateTransition(from: any, to: any): {
        valid: boolean;
        reason: string;
    };
    evaluateAbuseCase(context: any): {
        valid: boolean;
        violations: {
            id: any;
            message: any;
        }[];
    };
}
