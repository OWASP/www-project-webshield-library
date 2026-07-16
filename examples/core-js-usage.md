# Core JS Usage Example

## Goal

Show how to compose the `@owl/core` modules directly in a framework-agnostic application service.

## Bootstrap security services

```js
import {
  ACLManager,
  AuthManager,
  CSRFTokenManager,
  CryptoManager,
  DependencyRiskScanner,
  HardeningReporter,
  HTTPClient,
  InputSanitizer,
  InputValidator,
  PermissionChecker,
  RBACManager,
  SSRFGuard,
  SecurityConfigManager,
  SecurityLogger,
  TokenManager
} from "@owl/core";

const logger = new SecurityLogger();

const tokenManager = new TokenManager({
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

const authManager = new AuthManager({ tokenManager });
authManager.setSession({ userId: "u1", roles: ["editor"] });

const rbacManager = new RBACManager();
rbacManager.defineRole("editor", ["read:articles", "update:articles"]);

const aclManager = new ACLManager();
aclManager.setPolicy("articles", "delete", "deny");

const permissionChecker = new PermissionChecker({ rbacManager, aclManager });

const csrfManager = new CSRFTokenManager();
csrfManager.rotateToken();

const httpClient = new HTTPClient({
  baseUrl: "https://api.example.com",
  csrfManager,
  tokenProvider: async () => tokenManager.getAccessToken(),
  outboundRequestPolicy: new SSRFGuard()
});

httpClient.addRequestInterceptor(async (config) => ({
  ...config,
  headers: { ...config.headers, "X-Request-Id": "req-1" }
}));

const validator = new InputValidator();
const sanitizer = new InputSanitizer("moderate");
const cryptoManager = new CryptoManager();

const scanProvider = {
  scan: async () => [
    { name: "left-pad", severity: "high", currentVersion: "1.0.0", fixedVersion: "1.1.0" }
  ]
};

const dependencyScanner = new DependencyRiskScanner(scanProvider);

const configManager = new SecurityConfigManager({
  debug: false,
  cors: { origin: "self" },
  cookies: { secure: true, sameSite: "Strict" }
});

const hardeningReport = new HardeningReporter(configManager).generate();

logger.info("security.bootstrap.complete", {
  hardeningReportCount: hardeningReport.length
});
```

## Apply controls in request handling

```js
export async function updateArticle(body) {
  const validation = validator.validateSchema(body, {
    title: { required: true, minLength: 3 },
    content: { required: true, minLength: 10 }
  });

  if (!validation.valid) {
    logger.warn("article.validation.failed", { errors: validation.errors });
    return { ok: false, errors: validation.errors };
  }

  const permission = permissionChecker.check({
    role: authManager.getSession()?.roles?.[0],
    action: "update",
    resource: "articles"
  });

  if (!permission.allowed) {
    logger.warn("article.permission.denied", permission.metadata);
    return { ok: false, reason: permission.reason };
  }

  const cleanContent = sanitizer.sanitizeHTML(body.content);
  const { key } = cryptoManager.deriveKey("tenant-secret");
  const encryptedBody = cryptoManager.encrypt(cleanContent, key);

  const response = await httpClient.request("/articles/42", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title: body.title, content: encryptedBody })
  });

  if (!response.ok) {
    logger.error("article.update.failed", { status: response.status, error: response.error?.details });
    throw response.error;
  }

  return response.data;
}
```

## Run periodic operational checks

```js
export async function runSecurityChecks() {
  const dependencyGate = await dependencyScanner.passesPolicy("high");

  if (!dependencyGate.pass) {
    logger.error("dependency.policy.failed", { blocked: dependencyGate.blocked });
  }

  if (tokenManager.isAccessTokenExpired()) {
    await tokenManager.refreshIfNeeded();
  }

  return {
    dependencyGate,
    authenticated: authManager.isAuthenticated(),
    csrfToken: csrfManager.getToken()
  };
}
```

## Notes

- `HTTPClient` accepts both synchronous and asynchronous `tokenProvider` functions.
- `PermissionChecker` combines RBAC and ACL with deny-overrides behavior.
- `AuthManager.isAuthenticated()` depends on both a live session and a non-expired access token.

## Runnable Example

See [examples/core-node-demo/README.md](./core-node-demo/README.md) for a runnable version of this flow.