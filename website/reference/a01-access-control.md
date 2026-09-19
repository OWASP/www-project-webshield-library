# A01 — Broken Access Control

Deterministic, deny-overrides access control combining role-based (`RBACManager`) and resource-level (`ACLManager`) policies through a single `PermissionChecker`.

## Core API (`@owasp-core/owl`)

```js
import {
  ACLManager,
  ACCESS_CONTROL_TYPES,
  PermissionChecker,
  RBACManager
} from "@owasp-core/owl";

const rbac = new RBACManager();
rbac.defineRole("viewer", ["read:reports"]);
rbac.defineRole("analyst", ["export:reports"], ["viewer"]);
rbac.defineRole("support", ["read:*"]);

const acl = new ACLManager();
acl.setPolicy("reports", "delete", "deny");
acl.setPolicy("*", "read", "allow");

const checker = new PermissionChecker({ rbacManager: rbac, aclManager: acl });

checker.check({ role: "analyst", action: "read", resource: "reports" });
checker.check({ role: "support", action: "read", resource: "tickets" });
console.log(ACCESS_CONTROL_TYPES);
```

- `RBACManager` resolves inherited permissions and wildcard grants.
- `ACLManager` applies direct or wildcard policies with deterministic deny overrides.
- `PermissionChecker` combines RBAC and ACL and returns `{ allowed, reason, metadata }`.
- `ACCESS_CONTROL_TYPES` is a reserved runtime placeholder for category-local type exports.

## React Adapter (`@owasp-core/owl-react`)

```jsx
import React from "react";
import {
  ACLContext,
  ACLProvider,
  PermissionGate,
  RBACContext,
  RBACProvider,
  useACL,
  usePermission
} from "@owasp-core/owl-react";

function DeleteButton() {
  const aclManager = useACL();
  const permission = usePermission("delete", "reports");
  const aclContext = React.useContext(ACLContext);
  const rbacContext = React.useContext(RBACContext);

  return (
    <button disabled={!permission.allowed} data-acl={Boolean(aclContext)} data-rbac={Boolean(rbacContext)}>
      {aclManager.evaluate("reports", "delete").effect}
    </button>
  );
}

export function AccessControlExample({ aclManager, rbacManager }) {
  return (
    <ACLProvider aclManager={aclManager}>
      <RBACProvider rbacManager={rbacManager}>
        <PermissionGate action="delete" resource="reports" fallback={<span>Denied</span>}>
          <DeleteButton />
        </PermissionGate>
      </RBACProvider>
    </ACLProvider>
  );
}
```
