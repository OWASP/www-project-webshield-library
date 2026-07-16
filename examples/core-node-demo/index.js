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
} from "../../src/index.js";

const logger = new SecurityLogger({
  sink: (entry) => {
    console.log(`[${entry.level}] ${entry.event}`, entry.details);
  }
});

function createSecurityRuntime() {
  const tokenManager = new TokenManager({
    now: () => Date.now(),
    onRefresh: async (refreshToken) => ({
      accessToken: `rotated-${refreshToken}`,
      refreshToken,
      expiresAt: Date.now() + 60_000
    })
  });

  tokenManager.setTokens({
    accessToken: "access-token-1",
    refreshToken: "refresh-token-1",
    expiresAt: Date.now() + 30_000
  });

  const authManager = new AuthManager({ tokenManager });
  authManager.setSession({ userId: "editor-1", roles: ["editor"], metadata: { team: "content" } });

  const rbacManager = new RBACManager();
  rbacManager.defineRole("viewer", ["read:articles"]);
  rbacManager.defineRole("editor", ["update:articles"], ["viewer"]);

  const aclManager = new ACLManager();
  aclManager.setPolicy("articles", "read", "allow");
  aclManager.setPolicy("articles", "update", "allow");
  aclManager.setPolicy("articles", "delete", "deny");

  const permissionChecker = new PermissionChecker({ rbacManager, aclManager });

  const csrfManager = new CSRFTokenManager();
  csrfManager.rotateToken();

  const httpClient = new HTTPClient({
    baseUrl: "https://api.example.com",
    csrfManager,
    tokenProvider: async () => tokenManager.getAccessToken(),
    outboundRequestPolicy: new SSRFGuard(),
    fetchImpl: async (url, options) => ({
      ok: true,
      status: 200,
      headers: new Headers(),
      clone: () => ({
        json: async () => ({
          saved: true,
          url,
          headers: options.headers,
          body: JSON.parse(options.body)
        })
      }),
      text: async () => "ok"
    })
  });

  httpClient.addRequestInterceptor(async (config) => ({
    ...config,
    headers: {
      ...config.headers,
      "X-Request-Id": "core-demo-1"
    }
  }));

  const inputValidator = new InputValidator();
  const inputSanitizer = new InputSanitizer("moderate");
  const cryptoManager = new CryptoManager();

  const dependencyScanner = new DependencyRiskScanner({
    scan: async () => [
      {
        name: "markdown-parser",
        severity: "medium",
        currentVersion: "2.1.0",
        fixedVersion: "2.1.3"
      }
    ]
  });

  const configManager = new SecurityConfigManager({
    debug: false,
    cors: { origin: "self" },
    cookies: { secure: true, sameSite: "Strict" }
  });

  return {
    tokenManager,
    authManager,
    permissionChecker,
    httpClient,
    inputValidator,
    inputSanitizer,
    cryptoManager,
    dependencyScanner,
    configManager
  };
}

async function updateArticle(runtime, body) {
  const validation = runtime.inputValidator.validateSchema(body, {
    title: { required: true, minLength: 3 },
    content: { required: true, minLength: 10 }
  });

  if (!validation.valid) {
    logger.warn("article.validation.failed", { errors: validation.errors });
    return { ok: false, reason: "validation_failed", errors: validation.errors };
  }

  const permission = runtime.permissionChecker.check({
    role: runtime.authManager.getSession()?.roles?.[0],
    action: "update",
    resource: "articles"
  });

  if (!permission.allowed) {
    logger.warn("article.permission.denied", permission.metadata);
    return { ok: false, reason: permission.reason };
  }

  const cleanContent = runtime.inputSanitizer.sanitizeHTML(body.content);
  const { key } = runtime.cryptoManager.deriveKey("tenant-demo-secret");
  const encryptedContent = runtime.cryptoManager.encrypt(cleanContent, key);

  const response = await runtime.httpClient.request("/articles/42", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title: body.title, content: encryptedContent })
  });

  logger.info("article.updated", { status: response.status, saved: response.data.saved });
  return response.data;
}

async function runOperationalChecks(runtime) {
  const dependencyGate = await runtime.dependencyScanner.passesPolicy("high");
  const hardeningReport = new HardeningReporter(runtime.configManager).generate();

  logger.info("operational.checks", {
    dependencyPass: dependencyGate.pass,
    hardeningFindings: hardeningReport.length,
    authenticated: runtime.authManager.isAuthenticated()
  });

  return { dependencyGate, hardeningReport };
}

async function main() {
  const runtime = createSecurityRuntime();

  const article = await updateArticle(runtime, {
    title: "Quarterly security review",
    content: '<p onclick="alert(1)">Approved copy with <strong>safe formatting</strong>.</p>'
  });

  const checks = await runOperationalChecks(runtime);

  console.log("\nCore demo result");
  console.log(JSON.stringify({ article, checks }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});