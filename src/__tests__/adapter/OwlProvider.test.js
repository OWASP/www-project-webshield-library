import React from "react";
import { describe, expect, test } from "@jest/globals";
import { render, screen } from "@testing-library/react";
import { OwlProvider, useAuth, usePermission, useSecurityMonitoring } from "../../adapters/react/index.js";
import { createOwlClient } from "../../core/index.js";

function Probe() {
  const { session } = useAuth();
  const permission = usePermission("read", "todos");
  const { logger } = useSecurityMonitoring();
  return React.createElement(
    "div",
    null,
    `${session?.userId}:${permission.allowed}:${Boolean(logger)}`
  );
}

describe("OwlProvider", () => {
  test("composes Security/Auth/ACL/RBAC providers from a createOwlClient() result", () => {
    const owl = createOwlClient({ roles: { viewer: { permissions: ["read:todos"] } } });
    owl.authManager.setSession({ userId: "riley", roles: ["viewer"] });

    render(
      React.createElement(OwlProvider, { client: owl }, React.createElement(Probe))
    );

    expect(screen.getByText("riley:true:true").textContent).toBe("riley:true:true");
  });

  test("individual manager props override the client prop", () => {
    const base = createOwlClient({ roles: { viewer: { permissions: ["read:todos"] } } });
    const override = createOwlClient({ roles: { viewer: { permissions: [] } } });
    base.authManager.setSession({ userId: "riley", roles: ["viewer"] });
    override.authManager.setSession({ userId: "avery", roles: ["viewer"] });

    render(
      React.createElement(
        OwlProvider,
        { client: base, authManager: override.authManager, rbacManager: override.rbacManager },
        React.createElement(Probe)
      )
    );

    // authManager/rbacManager come from the override; aclManager/logger/events still from base.
    expect(screen.getByText("avery:false:true").textContent).toBe("avery:false:true");
  });
});
