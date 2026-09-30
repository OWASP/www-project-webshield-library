// Plain root-package imports — safe now that both @owasp-webshield/core and
// @owasp-webshield/react ship a "browser" build where CryptoManager (the one
// piece with no browser equivalent) is a same-shaped throwing stub instead of
// a build-breaking import. See the FAQ: "Can I use OWL in a browser bundle?"
import {
  ComponentPolicy,
  createOwlClient,
  CSRFTokenManager,
  DesignChecklist,
  HTTPClient,
  InputValidator,
  SecretPolicy,
  SSRFGuard
} from "@owasp-webshield/core";

const owl = createOwlClient({
  roles: {
    member: { permissions: ["read:todos", "write:todos", "read:security"] },
    admin: {
      permissions: ["read:todos", "write:todos", "delete:todos", "read:security", "manage:security"],
      inherits: ["member"]
    }
  },
  acl: [
    { resource: "todos", action: "read", effect: "allow" },
    { resource: "todos", action: "write", effect: "allow" },
    // Deny-override demo: RBAC grants "delete:todos" to admins, but this ACL
    // policy still blocks it — nobody can delete tasks in this demo.
    { resource: "todos", action: "delete", effect: "deny" },
    { resource: "security", action: "manage", effect: "allow" }
  ],
  token: { now: () => Date.now() },
  logger: { sink: (entry) => console.log("[owl-todo]", entry) }
});
const { tokenManager, authManager, rbacManager, aclManager, events, logger } = owl;

export const csrfManager = new CSRFTokenManager();
csrfManager.rotateToken();

export const ssrfGuard = new SSRFGuard();

export const apiClient = new HTTPClient({
  baseUrl: "https://api.todo.example.com",
  csrfManager,
  tokenProvider: () => tokenManager.getAccessToken(),
  outboundRequestPolicy: ssrfGuard,
  fetchImpl: async (_url, options) => ({
    ok: true,
    status: 200,
    headers: options?.headers || {},
    clone: () => ({ json: async () => ({ status: "ok", source: "owl-todo-mock-api" }) }),
    text: async () => "ok"
  })
});

export const inputValidator = new InputValidator();

export const designChecklist = new DesignChecklist([
  "role_based_access_control",
  "deny_override_acl",
  "csrf_protection",
  "input_sanitization",
  "ssrf_guard",
  "structured_security_logging"
]);

export const componentPolicy = new ComponentPolicy({
  denylist: ["legacy-parser"],
  minVersions: { "date-tool": "3.1.1" }
});

export const dependencyProvider = {
  async scan() {
    return [
      { name: "legacy-parser", severity: "high", currentVersion: "1.8.2", fixedVersion: "1.8.9" },
      { name: "date-tool", severity: "low", currentVersion: "3.1.0", fixedVersion: "3.1.1" },
      { name: "markdown-render", severity: "medium", currentVersion: "4.0.0", fixedVersion: "4.0.1" }
    ];
  }
};

const DEMO_USERS = {
  member: { userId: "riley", roles: ["member"] },
  admin: { userId: "avery", roles: ["admin"] }
};

function emitActivity(type, actor, details = {}) {
  events.emit("activity", { ts: new Date().toISOString(), type, actor, details });
}

export function login(role) {
  const user = DEMO_USERS[role];
  if (!user) return;
  tokenManager.setTokens({
    accessToken: `demo.${role}.${csrfManager.generateToken().slice(0, 12)}`,
    expiresAt: Date.now() + 30 * 60 * 1000
  });
  csrfManager.rotateToken();
  authManager.setSession(user);
  logger.info("auth.login", { userId: user.userId, role });
  emitActivity("login", user.userId);
}

export function logout() {
  const session = authManager.getSession();
  logger.info("auth.logout", { userId: session?.userId });
  emitActivity("logout", session?.userId || "unknown");
  authManager.clearSession();
}

export const security = {
  tokenManager,
  authManager,
  rbacManager,
  aclManager,
  events,
  logger,
  apiClient,
  ssrfGuard,
  inputValidator,
  designChecklist,
  componentPolicy,
  dependencyProvider,
  login,
  logout
};

export { SecretPolicy };
