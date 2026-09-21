import { describe, expect, test } from "@jest/globals";
import { createOwlClient } from "../../core/createOwlClient.js";
import { PermissionChecker } from "../../core/a01-access-control/PermissionChecker.js";

describe("createOwlClient", () => {
  test("wires roles and ACL policies declaratively", () => {
    const owl = createOwlClient({
      roles: {
        viewer: { permissions: ["read:todos"] },
        admin: { permissions: ["delete:todos"], inherits: ["viewer"] }
      },
      acl: [{ resource: "todos", action: "delete", effect: "deny" }]
    });

    expect(owl.rbacManager.can("admin", "read", "todos")).toBe(true);

    const checker = new PermissionChecker({ rbacManager: owl.rbacManager, aclManager: owl.aclManager });
    const decision = checker.check({ role: "admin", action: "delete", resource: "todos" });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("acl_deny_override");
  });

  test("wires authManager to the same tokenManager instance", () => {
    const owl = createOwlClient({ token: { now: () => 1000 } });
    owl.tokenManager.setTokens({ accessToken: "t1", expiresAt: 2000 });
    owl.authManager.setSession({ userId: "u1", roles: ["viewer"] });

    expect(owl.authManager.isAuthenticated()).toBe(true);
    expect(owl.authManager.tokenManager).toBe(owl.tokenManager);
  });

  test("returns working logger and event emitter", () => {
    const entries = [];
    const owl = createOwlClient({ logger: { sink: (entry) => entries.push(entry) } });
    owl.logger.info("test.event", { password: "secret" });

    expect(entries).toHaveLength(1);
    expect(entries[0].details.password).toBe("[REDACTED]");
  });

  test("defaults to empty roles/ACL when no config given", () => {
    const owl = createOwlClient();
    expect(owl.rbacManager.can("anyone", "read", "anything")).toBe(false);
    expect(owl.aclManager.evaluate("anything", "read")).toEqual({ effect: "neutral", allowed: false });
  });
});
