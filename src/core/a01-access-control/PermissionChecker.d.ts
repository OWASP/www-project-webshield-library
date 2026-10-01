export class PermissionChecker {
    /**
     * @param {{rbacManager: import('./RBACManager.js').RBACManager, aclManager: import('./ACLManager.js').ACLManager}} options
     */
    constructor(options: {
        rbacManager: import("./RBACManager.js").RBACManager;
        aclManager: import("./ACLManager.js").ACLManager;
    });
    rbacManager: import("./RBACManager.js").RBACManager;
    aclManager: import("./ACLManager.js").ACLManager;
    check({ role, action, resource }: {
        role: any;
        action: any;
        resource: any;
    }): {
        allowed: boolean;
        reason: string;
        metadata: {
            rbacAllowed: boolean;
            aclResult: {
                effect: any;
                allowed: boolean;
            };
        };
    };
}
