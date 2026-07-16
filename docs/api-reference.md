---
render_with_liquid: false
---

# OWASP Web Shield Library API Reference

This page documents the public runtime API exported by `@owl/core` and `@owl/react-adapter`.

## End-to-End Composition

```jsx
import React from "react";
import {
  ACLManager,
  AuthManager,
  CSRFTokenManager,
  HTTPClient,
  RBACManager,
  SSRFGuard,
  TokenManager
} from "@owl/core";
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
} from "@owl/react-adapter";

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

## Core API

### A01 Access Control

```js
import {
  ACLManager,
  ACCESS_CONTROL_TYPES,
  PermissionChecker,
  RBACManager
} from "@owl/core";

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

### A02 Crypto Integrity

```js
import {
  Argon2Adapter,
  CryptoManager,
  PBKDF2Adapter,
  SecretPolicy,
  generateSalt
} from "@owl/core";

const salt = generateSalt();
const crypto = new CryptoManager({
  kdfAdapter: new PBKDF2Adapter({ iterations: 210000, keyLength: 32, digest: "sha256" })
});

const { key } = crypto.deriveKey("correct-horse-battery-staple", salt);
const encrypted = crypto.encrypt("sensitive payload", key);
const decrypted = crypto.decrypt(encrypted, key);

const argon2 = new Argon2Adapter({
  deriveFn: (_password, deriveSalt) => Buffer.concat([deriveSalt, Buffer.alloc(32)]).subarray(0, 32)
});
argon2.deriveKey("password", salt, { memoryCost: 19456 });

SecretPolicy.isEntropySufficient("correct-horse-battery-staple", 60);
SecretPolicy.isRotationWindowExceeded(Date.now() - 86_500_000, 86_400_000);
```

### A03 Injection Defense

```js
import {
  INJECTION_DEFENSE_TYPES,
  InputSanitizer,
  InputValidator
} from "@owl/core";

const sanitizer = new InputSanitizer("moderate");
const cleanHtml = sanitizer.sanitizeHTML('<a href="javascript:alert(1)" onclick="alert(1)">safe</a>');

const validator = new InputValidator();
const validation = validator.validateSchema(
  { email: "user@example.com", password: "secret-123" },
  {
    email: { required: true, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
    password: { required: true, minLength: 8 }
  }
);

validator.validateEmail("user@example.com");
validator.validateUrl("https://example.com/profile");
validator.validateLength("secret-123", { min: 8, max: 64 });
console.log(cleanHtml, validation.valid, INJECTION_DEFENSE_TYPES);
```

### A04 Insecure Design Guard

```js
import { DesignChecklist, ThreatModelGuard } from "@owl/core";

const guard = new ThreatModelGuard({
  transitions: { draft: ["review"], review: ["approved"] },
  abuseRules: [
    { id: "mfa", message: "MFA required", check: (context) => context.mfaVerified === true },
    { id: "rate-limit", message: "Too many attempts", check: (context) => context.attempts < 5 }
  ]
});

guard.validateTransition("draft", "review");
guard.evaluateAbuseCase({ mfaVerified: false, attempts: 7 });

const checklist = new DesignChecklist(["2fa", "audit-log", "csrf"]);
checklist.validate(["2fa", "audit-log"]);
```

### A05 Security Misconfiguration

```js
import { HardeningReporter, SecurityConfigManager } from "@owl/core";

const configManager = new SecurityConfigManager({
  debug: true,
  cors: { origin: "*" },
  cookies: { secure: false, sameSite: "None" }
});

configManager.validateSchema();
const findings = configManager.detectUnsafeSettings();
const report = new HardeningReporter(configManager).generate();

console.log(findings, report);
```

### A06 Vulnerable Components

```js
import { ComponentPolicy, DependencyRiskScanner } from "@owl/core";

const scanner = new DependencyRiskScanner({
  scan: async () => [
    { name: "left-pad", severity: "high", currentVersion: "1.0.0", fixedVersion: "1.1.0" }
  ]
});

const results = await scanner.scan();
const gate = await scanner.passesPolicy("high");

const policy = new ComponentPolicy({
  allowlist: ["left-pad", "react"],
  denylist: ["unsafe-lib"],
  minVersions: { react: "18.3.1" }
});

policy.evaluate({ name: "react", version: "18.3.1" });
console.log(results, gate.pass);
```

### A07 Auth Session

```js
import { AuthManager, AUTH_TYPES, TokenManager } from "@owl/core";

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

### A08 Data Integrity

```js
import { CSRFTokenManager, DATA_INTEGRITY_TYPES, HTTPClient, SSRFGuard } from "@owl/core";

const csrf = new CSRFTokenManager();
csrf.rotateToken();
csrf.attach({});
csrf.validate(csrf.getToken());

const client = new HTTPClient({
  baseUrl: "https://api.example.com",
  csrfManager: csrf,
  tokenProvider: async () => "access-token",
  outboundRequestPolicy: new SSRFGuard()
});

client.addRequestInterceptor(async (config) => ({
  ...config,
  headers: { ...config.headers, "X-Request-Id": "req-1" }
}));

const response = await client.request("/profile", { method: "GET" });
console.log(response.ok, response.data, DATA_INTEGRITY_TYPES);
```

- `HTTPClient` accepts a `tokenProvider` function that may return a string, `null`, or a promise for either value. The client always awaits it before sending the request.

### A09 Logging Monitoring

```js
import { EventEmitter, SecurityLogger } from "@owl/core";

const events = new EventEmitter();
const logger = new SecurityLogger({
  sink: (entry) => {
    console.log(entry.level, entry.event, entry.details);
  }
});

const unsubscribe = events.on("auth:changed", (payload) => {
  logger.info("auth.changed", payload);
});

events.emit("auth:changed", {
  userId: "u1",
  authorization: "Bearer abc",
  password: "secret"
});

logger.warn("security.warning", { token: "abc", keep: "value" });
logger.error("security.error", { cookie: "session=1" });
unsubscribe();
```

### A10 SSRF Defense

```js
import { SSRFGuard, SafeFetcher } from "@owl/core";

const guard = new SSRFGuard({ allowProtocols: ["https:"], maxRedirectHops: 2 });
guard.validateUrl("https://api.example.com/users");
guard.validateRedirectChain(["https://a.example.com", "https://b.example.com"]);

const safeFetcher = new SafeFetcher({
  guard,
  fetchImpl: fetch
});

await safeFetcher.fetch("https://api.example.com/users", { method: "GET" });
```

### Typed Errors

```js
import { SecurityError, SecurityErrorCode } from "@owl/core";

throw new SecurityError(SecurityErrorCode.ACCESS_DENIED, "Report access denied", {
  action: "read",
  resource: "reports"
});
```

## React Adapter API

### A07 Provider Composition

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
} from "@owl/react-adapter";

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

- `useAuthToken()` updates when the underlying `TokenManager` emits `token:changed`, `token:cleared`, or `token:rotated`.
- `AuthProvider` also schedules an auth-state recheck at `expiresAt`, so `AuthGate` falls back automatically once the token expires.

### A01 Access Control Adapter

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
} from "@owl/react-adapter";

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

### A02 Crypto Adapter

```jsx
import React from "react";
import { useCryptoManager } from "@owl/react-adapter";

export function PasswordPreview() {
  const crypto = useCryptoManager();

  function handleDerive() {
    const { key, salt } = crypto.deriveKey("correct-horse-battery-staple");
    console.log(key.length, salt.toString("base64"));
  }

  return <button onClick={handleDerive}>Derive key</button>;
}
```

### A03 Injection Defense Adapter

```jsx
import React from "react";
import { SanitizedText, useInputSanitizer } from "@owl/react-adapter";

export function CommentPreview({ rawHtml }) {
  const sanitizer = useInputSanitizer("moderate");
  const clean = sanitizer.sanitizeHTML(rawHtml);

  return (
    <div>
      <div>{clean}</div>
      <SanitizedText profile="strict" html={rawHtml} />
    </div>
  );
}
```

### A04 Insecure Design Adapter

```jsx
import React from "react";
import { useThreatModelGuard } from "@owl/react-adapter";

export function WorkflowActions() {
  const guard = useThreatModelGuard({ transitions: { draft: ["review"], review: ["approved"] } });
  const transition = guard.validateTransition("draft", "review");

  return <button disabled={!transition.valid}>Submit for review</button>;
}
```

### A05 Misconfiguration Adapter

```jsx
import React from "react";
import { useHardeningReport } from "@owl/react-adapter";

export function ConfigDashboard({ config }) {
  const findings = useHardeningReport(config);

  return (
    <ul>
      {findings.map((finding) => (
        <li key={finding.id}>{finding.recommendation}</li>
      ))}
    </ul>
  );
}
```

### A06 Vulnerable Components Adapter

```jsx
import React from "react";
import { useDependencyRiskScanner } from "@owl/react-adapter";

export function DependencyPanel({ provider }) {
  const { loading, results, error, runScan } = useDependencyRiskScanner(provider);

  React.useEffect(() => {
    runScan().catch(() => {});
  }, [runScan]);

  if (loading) return <div>Scanning...</div>;
  if (error) return <div>{error.message}</div>;
  return <pre>{JSON.stringify(results, null, 2)}</pre>;
}
```

- `runScan` is stable for a stable mounted hook instance and always uses the latest provider supplied to the hook.
- The hook state shape is `{ loading, results, error, runScan, scanner }`.

### A08 Data Integrity Adapter

```jsx
import React from "react";
import { useSecureHttpClient, withSecurityHeaders } from "@owl/react-adapter";

export function ProfileLoader({ tokenManager }) {
  const client = useSecureHttpClient({
    baseUrl: "https://api.example.com",
    tokenProvider: async () => tokenManager.getAccessToken()
  });

  async function loadProfile() {
    const response = await client.request(
      "/profile",
      withSecurityHeaders({
        method: "GET",
        headers: { "X-Feature": "profile-view" }
      })
    );

    console.log(response.data);
  }

  return <button onClick={loadProfile}>Load profile</button>;
}
```

- `useSecureHttpClient()` creates one `CSRFTokenManager` per hook instance and rotates a token during initialization.
- `withSecurityHeaders()` adds OWL defaults and preserves caller-supplied headers.

### A09 Logging Monitoring Adapter

```jsx
import React from "react";
import {
  SecurityAlert,
  SecurityContext,
  SecurityProvider,
  useSecurityMonitoring
} from "@owl/react-adapter";

function SecurityStatus() {
  const { logger, events } = useSecurityMonitoring();
  const securityContext = React.useContext(SecurityContext);

  React.useEffect(() => {
    logger?.info("security.status.rendered", { hasEvents: Boolean(events) });
  }, [logger, events]);

  return (
    <div>
      <div>{securityContext.logger ? "monitoring-enabled" : "monitoring-disabled"}</div>
      <SecurityAlert level="warn" message="Review recent security events" />
    </div>
  );
}

export function MonitoringExample({ logger, events }) {
  return (
    <SecurityProvider logger={logger} events={events}>
      <SecurityStatus />
    </SecurityProvider>
  );
}
```

- `useSecurityMonitoring()` is safe to call without a provider and returns `{ logger: null, events: null }`.
- `SecurityAlert` is a simple presentational component that renders a role=`alert` container with a `data-level` attribute.

### A10 SSRF Defense Adapter

```jsx
import React from "react";
import { useSafeFetcher } from "@owl/react-adapter";

export function RemoteConfigLoader() {
  const safeFetcher = useSafeFetcher({ allowProtocols: ["https:"] }, fetch);

  async function loadConfig() {
    const response = await safeFetcher.fetch("https://config.example.com/runtime.json");
    console.log(response.ok);
  }

  return <button onClick={loadConfig}>Load config</button>;
}
```