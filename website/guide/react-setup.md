# React Adapter Setup

Install the adapter alongside the core package:

```bash
npm install @owasp-core/owl @owasp-core/owl-react
```

The adapter mirrors the core module structure one-for-one: every OWASP category that has a manager or class in `@owasp-core/owl` has a matching provider and hook set in `@owasp-core/owl-react`.

## Full provider composition

Most apps wire up several providers at once — `SecurityProvider` for logging/monitoring, `AuthProvider` for session state, and `ACLProvider` / `RBACProvider` for access control — then gate content with `AuthGate` and `PermissionGate`:

```jsx
import React from "react";
import {
  TokenManager,
  AuthManager,
  ACLManager,
  RBACManager
} from "@owasp-core/owl";
import {
  ACLProvider,
  AuthGate,
  AuthProvider,
  PermissionGate,
  RBACProvider,
  SecurityAlert,
  SecurityProvider,
  useSafeFetcher,
  useSecureHttpClient
} from "@owasp-core/owl-react";

const tokenManager = new TokenManager({
  onRefresh: async (refreshToken) => ({
    accessToken: `rotated-${refreshToken}`,
    refreshToken,
    expiresAt: Date.now() + 60_000
  })
});

const authManager = new AuthManager({ tokenManager });
authManager.setSession({ userId: "u1", roles: ["editor"] });

const aclManager = new ACLManager();
const rbacManager = new RBACManager();
rbacManager.defineRole("editor", ["read:articles", "update:articles"]);
aclManager.setPolicy("articles", "delete", "deny");

function SecureArticleList() {
  const client = useSecureHttpClient({
    baseUrl: "https://api.example.com",
    tokenProvider: () => tokenManager.getAccessToken()
  });
  const safeFetcher = useSafeFetcher({ allowProtocols: ["https:"] });

  async function loadArticles() {
    const response = await client.request("/articles", { method: "GET" });
    await safeFetcher.fetch("https://cdn.example.com/articles.json");
    return response.data;
  }

  return <button onClick={loadArticles}>Load articles</button>;
}

export function App() {
  return (
    <SecurityProvider logger={logger} events={events}>
      <AuthProvider authManager={authManager}>
        <ACLProvider aclManager={aclManager}>
          <RBACProvider rbacManager={rbacManager}>
            <AuthGate fallback={<SecurityAlert level="warn" message="Please sign in" />}>
              <PermissionGate
                action="read"
                resource="articles"
                fallback={<SecurityAlert level="error" message="Access denied" />}
              >
                <SecureArticleList />
              </PermissionGate>
            </AuthGate>
          </RBACProvider>
        </ACLProvider>
      </AuthProvider>
    </SecurityProvider>
  );
}
```

::: tip
Every provider is independent — you only need to mount the ones for the categories you're actually using. A component tree that only needs input sanitization, for example, needs no providers at all: `useInputSanitizer()` works standalone.
:::

## Where to go next

Each category's [reference page](/reference/a01-access-control) documents its own hooks and components (e.g. `usePermission`, `useCryptoManager`, `useSafeFetcher`) alongside the equivalent core API, so you can see both sides together.
