export class PermissionChecker {
  /**
   * @param {{rbacManager: import('./RBACManager.js').RBACManager, aclManager: import('./ACLManager.js').ACLManager}} options
   */
  constructor(options) {
    this.rbacManager = options.rbacManager;
    this.aclManager = options.aclManager;
  }

  check({ role, action, resource }) {
    const rbacAllowed = this.rbacManager.can(role, action, resource);
    const aclResult = this.aclManager.evaluate(resource, action);

    if (aclResult.effect === "deny") {
      return { allowed: false, reason: "acl_deny_override", metadata: { rbacAllowed, aclResult } };
    }

    if (!rbacAllowed) {
      return { allowed: false, reason: "rbac_denied", metadata: { rbacAllowed, aclResult } };
    }

    return { allowed: true, reason: "allowed", metadata: { rbacAllowed, aclResult } };
  }
}