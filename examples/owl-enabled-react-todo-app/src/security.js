// Imported by relative path into src/core, NOT via the "@owasp-core/owl" package
// entry point. That entry resolves to the prebuilt dist/index.js, which bundles every
// core module — including a02-crypto-integrity/CryptoManager.js and its KDFAdapters,
// and a08-data-integrity/CSRFTokenManager.js — into one file with unconditional
// top-level `import ... from "node:crypto"` statements. In a browser bundle those
// imports resolve to a stub that throws on ANY property access the moment the module
// is evaluated, so merely importing anything from the package root crashes on load,
// regardless of which export is actually used. Importing each safe file directly (the
// same technique the adapter's own source already uses internally) avoids evaluating
// those Node-only files at all. See README "Notes" for the full explanation.
import { RBACManager } from "../../../src/core/a01-access-control/RBACManager.js";
import { ACLManager } from "../../../src/core/a01-access-control/ACLManager.js";
import { SecretPolicy } from "../../../src/core/a02-crypto-integrity/SecretPolicy.js";
import { InputValidator } from "../../../src/core/a03-injection-defense/InputValidator.js";
import { DesignChecklist } from "../../../src/core/a04-insecure-design-guard/DesignChecklist.js";
import { ComponentPolicy } from "../../../src/core/a06-vulnerable-components/ComponentPolicy.js";
import { AuthManager } from "../../../src/core/a07-auth-session/AuthManager.js";
import { TokenManager } from "../../../src/core/a07-auth-session/TokenManager.js";
import { HTTPClient } from "../../../src/core/a08-data-integrity/HTTPClient.js";
import { EventEmitter } from "../../../src/core/a09-logging-monitoring/EventEmitter.js";
import { SecurityLogger } from "../../../src/core/a09-logging-monitoring/SecurityLogger.js";
import { SSRFGuard } from "../../../src/core/a10-ssrf-defense/SSRFGuard.js";

// A real `CSRFTokenManager` instance is avoided for the same reason (its file has a
// top-level `node:crypto` import for `randomBytes`/`timingSafeEqual`). This mock keeps
// the exact interface `HTTPClient` expects (`attach(headers)`) and seeds itself via the
// browser-native Web Crypto API instead.
function browserRandomToken(byteLength = 24) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function createCsrfManager() {
  let token = browserRandomToken();
  return {
    rotate() {
      token = browserRandomToken();
      return token;
    },
    attach(headers = {}) {
      return { ...headers, "X-CSRF-Token": token };
    }
  };
}

export const tokenManager = new TokenManager({ now: () => Date.now() });
export const authManager = new AuthManager({ tokenManager });

export const rbacManager = new RBACManager();
rbacManager.defineRole("member", ["read:todos", "write:todos", "read:security"]);
rbacManager.defineRole(
  "admin",
  ["read:todos", "write:todos", "delete:todos", "read:security", "manage:security"],
  ["member"]
);

export const aclManager = new ACLManager();
aclManager.setPolicy("todos", "read", "allow");
aclManager.setPolicy("todos", "write", "allow");
// Deny-override demo: RBAC grants "delete:todos" to admins, but this ACL policy
// still blocks it. PermissionChecker's deny-overrides resolution means the ACL
// "deny" wins regardless of role — nobody can delete tasks in this demo.
aclManager.setPolicy("todos", "delete", "deny");
aclManager.setPolicy("security", "manage", "allow");

export const events = new EventEmitter();
export const logger = new SecurityLogger({
  sink: (entry) => console.log("[owl-todo]", entry)
});

export const csrfManager = createCsrfManager();

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
    accessToken: `demo.${role}.${browserRandomToken(8)}`,
    expiresAt: Date.now() + 30 * 60 * 1000
  });
  csrfManager.rotate();
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
