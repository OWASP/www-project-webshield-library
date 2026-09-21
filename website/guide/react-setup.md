# React Adapter Setup

Install the adapter alongside the core package:

```bash
npm install @owasp-webshield/core @owasp-webshield/react
```

The adapter mirrors the core module structure one-for-one: every OWASP category that has a manager or class in `@owasp-webshield/core` has a matching provider and hook set in `@owasp-webshield/react`.

## Full provider composition

Most apps wire up several providers at once — `SecurityProvider` for logging/monitoring, `AuthProvider` for session state, and `ACLProvider` / `RBACProvider` for access control — then gate content with `AuthGate` and `PermissionGate`. `createOwlClient()` (core) builds and wires the managers from one config object, and `OwlProvider` (adapter) composes the four providers into one component:

```jsx
import React from "react";
import { createOwlClient } from "@owasp-webshield/core";
import {
  AuthGate,
  OwlProvider,
  PermissionGate,
  SecurityAlert,
  useSafeFetcher,
  useSecureHttpClient
} from "@owasp-webshield/react";

const owl = createOwlClient({
  roles: { editor: { permissions: ["read:articles", "update:articles"] } },
  acl: [{ resource: "articles", action: "delete", effect: "deny" }],
  token: {
    onRefresh: async (refreshToken) => ({
      accessToken: `rotated-${refreshToken}`,
      refreshToken,
      expiresAt: Date.now() + 60_000
    })
  }
});
owl.authManager.setSession({ userId: "u1", roles: ["editor"] });

function SecureArticleList() {
  const client = useSecureHttpClient({
    baseUrl: "https://api.example.com",
    tokenProvider: () => owl.tokenManager.getAccessToken()
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
    <OwlProvider client={owl}>
      <AuthGate fallback={<SecurityAlert level="warn" message="Please sign in" />}>
        <PermissionGate
          action="read"
          resource="articles"
          fallback={<SecurityAlert level="error" message="Access denied" />}
        >
          <SecureArticleList />
        </PermissionGate>
      </AuthGate>
    </OwlProvider>
  );
}
```

::: tip
Every provider is independent — you only need to mount the ones for the categories you're actually using. A component tree that only needs input sanitization, for example, needs no providers at all: `useInputSanitizer()` works standalone. If you'd rather wire `SecurityProvider`/`AuthProvider`/`ACLProvider`/`RBACProvider` individually — useful if their managers come from different places — see [docs/react-adapter-usage.md](https://github.com/OWASP/www-project-webshield-library/blob/main/docs/react-adapter-usage.md) for the manual version `OwlProvider` composes.
:::

## Where to go next

Each category's [reference page](/reference/a01-access-control) documents its own hooks and components (e.g. `usePermission`, `useCryptoManager`, `useSafeFetcher`) alongside the equivalent core API, so you can see both sides together.
