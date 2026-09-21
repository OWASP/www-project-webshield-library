# A07 — Identification & Authentication Failures

`TokenManager` handles token storage, expiry scheduling, and refresh; `AuthManager` layers session state (user, roles, metadata) on top of it.

## Core API (`@owasp-js/owl`)

```js
import { AuthManager, AUTH_TYPES, TokenManager } from "@owasp-js/owl";

const tokenManager = new TokenManager({
  onRefresh: async (refreshToken, currentAccess) => ({
    accessToken: `${currentAccess}-next`,
    refreshToken,
    expiresAt: Date.now() + 60_000
  })
});

tokenManager.setTokens({
  accessToken: "access-1",
  refreshToken: "refresh-1",
  expiresAt: Date.now() + 30_000
});

const authManager = new AuthManager({ tokenManager });
authManager.setSession({ userId: "u1", roles: ["editor"], metadata: { tenant: "acme" } });

await tokenManager.refreshIfNeeded();
tokenManager.getAccessToken();
authManager.isAuthenticated();
authManager.clearSession();
console.log(AUTH_TYPES);
```

## React Adapter (`@owasp-js/owl-react`)

This is usually the first provider tree an app wires up, since most other guards (`PermissionGate`, `SecurityAlert`) render relative to auth state:

```jsx
import React from "react";
import {
  ACLProvider,
  AuthContext,
  AuthGate,
  AuthProvider,
  PermissionGate,
  RBACProvider,
  SecurityProvider,
  useAuth,
  useAuthToken
} from "@owasp-js/owl-react";

function SessionSummary() {
  const { session, isAuthenticated } = useAuth();
  const accessToken = useAuthToken();
  const authContext = React.useContext(AuthContext);

  return (
    <pre>
      {JSON.stringify({
        isAuthenticated,
        userId: session?.userId,
        tokenPreview: accessToken?.slice(0, 8),
        sameContext: authContext.session?.userId === session?.userId
      })}
    </pre>
  );
}

export function AuthTree({ authManager, aclManager, rbacManager, logger, events }) {
  return (
    <SecurityProvider logger={logger} events={events}>
      <AuthProvider authManager={authManager}>
        <ACLProvider aclManager={aclManager}>
          <RBACProvider rbacManager={rbacManager}>
            <AuthGate fallback={<div>Please sign in</div>}>
              <PermissionGate action="read" resource="reports" fallback={<div>Denied</div>}>
                <SessionSummary />
              </PermissionGate>
            </AuthGate>
          </RBACProvider>
        </ACLProvider>
      </AuthProvider>
    </SecurityProvider>
  );
}
```

Or use `OwlProvider` to compose those four providers in one component, paired with `createOwlClient()` to build the managers:

```jsx
import { createOwlClient } from "@owasp-js/owl";
import { AuthGate, OwlProvider, PermissionGate } from "@owasp-js/owl-react";

const owl = createOwlClient({ roles: { editor: { permissions: ["read:reports"] } } });
owl.authManager.setSession({ userId: "u1", roles: ["editor"] });

export function AuthTree({ children }) {
  return (
    <OwlProvider client={owl}>
      <AuthGate fallback={<div>Please sign in</div>}>
        <PermissionGate action="read" resource="reports" fallback={<div>Denied</div>}>
          {children}
        </PermissionGate>
      </AuthGate>
    </OwlProvider>
  );
}
```

- `useAuthToken()` updates when the underlying `TokenManager` emits `token:changed`, `token:cleared`, or `token:rotated`.
- `AuthProvider` also schedules an auth-state recheck at `expiresAt`, so `AuthGate` falls back automatically once the token expires.

See also: [React Adapter Setup](/guide/react-setup) for the full multi-category provider tree.
