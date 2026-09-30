export class ComponentPolicy {
    constructor({ allowlist, denylist, minVersions }?: {
        allowlist?: any;
        denylist?: any[];
        minVersions?: {};
    });
    allowlist: Set<any>;
    denylist: Set<any>;
    minVersions: {};
    evaluate(pkg: any): {
        allowed: boolean;
        reason: string;
        required?: undefined;
    } | {
        allowed: boolean;
        reason: string;
        required: any;
    };
}
