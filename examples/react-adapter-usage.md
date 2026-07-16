# React Adapter Usage Example

## Goal

Show how to wire `@owl/react-adapter` providers, hooks, and guard components around real `@owl/core` managers.

## Bootstrap managers once

```js
import {
  ACLManager,
  AuthManager,
  RBACManager,
  SecurityLogger,
  TokenManager
} from "@owl/core";

export const tokenManager = new TokenManager({
  onRefresh: async (refreshToken) => ({
    accessToken: `rotated-${refreshToken}`,
    refreshToken,
    expiresAt: Date.now() + 60_000
  })
});

tokenManager.setTokens({
  accessToken: "access-1",
  refreshToken: "refresh-1",
  expiresAt: Date.now() + 30_000
});

export const authManager = new AuthManager({ tokenManager });
authManager.setSession({ userId: "u1", roles: ["editor"] });

export const aclManager = new ACLManager();
aclManager.setPolicy("articles", "delete", "deny");

export const rbacManager = new RBACManager();
rbacManager.defineRole("editor", ["read:articles", "update:articles"]);

export const logger = new SecurityLogger();
export const events = { on: () => () => {} };
```

## Compose providers

```jsx
import React from "react";
import {
  ACLProvider,
  AuthGate,
  AuthProvider,
  PermissionGate,
  RBACProvider,
  SecurityAlert,
  SecurityProvider
} from "@owl/react-adapter";
import {
  aclManager,
  authManager,
  events,
  logger,
  rbacManager
} from "./security-bootstrap.js";

export function AppProviders({ children }) {
  return (
    <SecurityProvider logger={logger} events={events}>
      <AuthProvider authManager={authManager}>
        <ACLProvider aclManager={aclManager}>
          <RBACProvider rbacManager={rbacManager}>
            <AuthGate fallback={<SecurityAlert level="warn" message="Please sign in" />}>
              <PermissionGate
                action="read"
                resource="articles"
                fallback={<SecurityAlert level="error" message="Article access denied" />}
              >
                {children}
              </PermissionGate>
            </AuthGate>
          </RBACProvider>
        </ACLProvider>
      </AuthProvider>
    </SecurityProvider>
  );
}
```

## Use hooks in features

```jsx
import React from "react";
import {
  SanitizedText,
  useAuth,
  useAuthToken,
  useDependencyRiskScanner,
  useHardeningReport,
  useInputSanitizer,
  usePermission,
  useSafeFetcher,
  useSecureHttpClient,
  useSecurityMonitoring,
  useThreatModelGuard,
  withSecurityHeaders
} from "@owl/react-adapter";
import { tokenManager } from "./security-bootstrap.js";

export function ArticleWorkspace({ rawHtml }) {
  const { session, isAuthenticated } = useAuth();
  const token = useAuthToken();
  const permission = usePermission("update", "articles");
  const sanitizer = useInputSanitizer("moderate");
  const threatModel = useThreatModelGuard({
    transitions: { draft: ["review"], review: ["approved"] }
  });
  const hardeningReport = useHardeningReport({
    debug: false,
    cors: { origin: "self" },
    cookies: { secure: true, sameSite: "Strict" }
  });
  const scanner = useDependencyRiskScanner({
    scan: async () => [
      { name: "left-pad", severity: "medium", currentVersion: "1.0.0", fixedVersion: "1.1.0" }
    ]
  });
  const httpClient = useSecureHttpClient({
    baseUrl: "https://api.example.com",
    tokenProvider: async () => tokenManager.getAccessToken()
  });
  const safeFetcher = useSafeFetcher({ allowProtocols: ["https:"] }, fetch);
  const monitoring = useSecurityMonitoring();

  React.useEffect(() => {
    scanner.runScan().catch(() => {});
  }, [scanner.runScan]);

  async function loadArticles() {
    const response = await httpClient.request(
      "/articles",
      withSecurityHeaders({ method: "GET", headers: { "X-Feature": "workspace" } })
    );

    monitoring.logger?.info("articles.loaded", {
      userId: session?.userId,
      count: Array.isArray(response.data) ? response.data.length : 0
    });

    await safeFetcher.fetch("https://cdn.example.com/articles/index.json");
  }

  const sanitizedPreview = sanitizer.sanitizeHTML(rawHtml);
  const nextTransition = threatModel.validateTransition("draft", "review");

  return (
    <section>
      <h1>Article workspace</h1>
      <p>{isAuthenticated ? `Signed in as ${session?.userId}` : "Signed out"}</p>
      <p>{token ? `Token loaded: ${token.slice(0, 8)}...` : "No token"}</p>
      <p>{permission.allowed ? "Can update articles" : `Denied: ${permission.reason}`}</p>
      <p>{nextTransition.valid ? "Draft can move to review" : nextTransition.reason}</p>
      <p>Hardening findings: {hardeningReport.length}</p>
      <p>Dependency results: {scanner.results.length}</p>
      <button disabled={!permission.allowed} onClick={loadArticles}>Load articles</button>
      <div>{sanitizedPreview}</div>
      <SanitizedText html={rawHtml} profile="strict" />
    </section>
  );
}
```

## Notes

- `useAuthToken()` updates when the underlying token changes, clears, rotates, or expires.
- `useSecureHttpClient()` creates a single `CSRFTokenManager` per hook instance and supports async token providers.
- `useDependencyRiskScanner()` returns `{ loading, results, error, runScan, scanner }` and keeps `runScan` stable.
- `useSecurityMonitoring()` is safe without a provider, but the provider is recommended so logging and events are available.

## Runnable Example

See [examples/react-adapter-demo/README.md](./react-adapter-demo/README.md) for a runnable version of this flow.