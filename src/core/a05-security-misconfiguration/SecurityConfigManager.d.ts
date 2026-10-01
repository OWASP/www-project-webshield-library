export class SecurityConfigManager {
    constructor(config?: {});
    config: {
        cors: any;
        cookies: any;
        debug: boolean;
    };
    validateSchema(): boolean;
    detectUnsafeSettings(): {
        id: string;
        severity: string;
    }[];
}
