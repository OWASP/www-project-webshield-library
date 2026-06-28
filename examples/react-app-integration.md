# React App Integration Example

## Goal

Integrate OWL authorization, authentication, and transport controls in a React app shell.

## 1. Bootstrap managers

```js
import {
  ACLManager,
  AuthManager,
  RBACManager,
  TokenManager,
  CSRFTokenManager,
  HTTPClient,
  SSRFGuard
} from "@owl/core";

const tokenManager = new TokenManager();
const authManager = new AuthManager({ tokenManager });

const rbacManager = new RBACManager();
rbacManager.defineRole("admin", ["read:reports", "update:reports"]);

const aclManager = new ACLManager();
aclManager.setPolicy("reports", "delete", "deny");

const csrfManager = new CSRFTokenManager();
csrfManager.rotateToken();

export const apiClient = new HTTPClient({
  baseUrl: "https://api.example.com",
  csrfManager,
  tokenProvider: () => tokenManager.getAccessToken(),
  outboundRequestPolicy: new SSRFGuard()
});

export const security = { authManager, aclManager, rbacManager, tokenManager };
```

## 2. Compose providers

```jsx
import React from "react";
import {
  AuthProvider,
  ACLProvider,
  RBACProvider,
  AuthGate,
  PermissionGate
} from "@owl/react-adapter";
import { security } from "./security-bootstrap";

export function AppShell({ children }) {
  return (
    <AuthProvider authManager={security.authManager}>
      <ACLProvider aclManager={security.aclManager}>
        <RBACProvider rbacManager={security.rbacManager}>
          <AuthGate fallback={<div>Sign in required</div>}>
            <PermissionGate action="read" resource="reports" fallback={<div>Access denied</div>}>
              {children}
            </PermissionGate>
          </AuthGate>
        </RBACProvider>
      </ACLProvider>
    </AuthProvider>
  );
}
```

## 3. Use secure client in features

```js
import { apiClient } from "./security-bootstrap";

export async function fetchReports() {
  const response = await apiClient.request("/reports", { method: "GET" });
  if (!response.ok) throw response.error;
  return response.data;
}
```

## Security checklist

- Rotate CSRF token on auth boundary changes.
- Keep token storage in-memory unless persistence is explicitly required.
- Avoid bypassing PermissionGate in route-level components.
