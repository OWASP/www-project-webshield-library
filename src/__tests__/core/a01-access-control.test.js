import { describe, expect, test } from "@jest/globals";
import { ACLManager, PermissionChecker, RBACManager } from "../../core/a01-access-control/index.js";

describe("A01 access control", () => {
  test("supports role inheritance edge case", () => {
    const rbac = new RBACManager();
    rbac.defineRole("viewer", ["read:report"]);
    rbac.defineRole("analyst", ["export:report"], ["viewer"]);
    expect(rbac.can("analyst", "read", "report")).toBe(true);
    expect(rbac.can("analyst", "export", "report")).toBe(true);
  });

  test("matches wildcard permissions and wildcard ACL policies", () => {
    const rbac = new RBACManager();
    const acl = new ACLManager();
    rbac.defineRole("support", ["read:*"]);
    acl.setPolicy("*", "read", "allow");

    expect(rbac.can("support", "read", "ticket")).toBe(true);
    expect(acl.evaluate("ticket", "read")).toEqual({ effect: "allow", allowed: true });
  });

  test("acl deny overrides rbac allow", () => {
    const rbac = new RBACManager();
    const acl = new ACLManager();
    rbac.defineRole("admin", ["delete:invoice"]);
    acl.setPolicy("invoice", "delete", "deny");

    const checker = new PermissionChecker({ rbacManager: rbac, aclManager: acl });
    const result = checker.check({ role: "admin", action: "delete", resource: "invoice" });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("acl_deny_override");
  });

  test("permission checker reports rbac denial metadata", () => {
    const rbac = new RBACManager();
    const acl = new ACLManager();
    acl.setPolicy("invoice", "read", "allow");

    const checker = new PermissionChecker({ rbacManager: rbac, aclManager: acl });
    const result = checker.check({ role: "viewer", action: "read", resource: "invoice" });

    expect(result).toMatchObject({
      allowed: false,
      reason: "rbac_denied",
      metadata: {
        rbacAllowed: false,
        aclResult: { effect: "allow", allowed: true }
      }
    });
  });
});