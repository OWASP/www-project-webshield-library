import {
  ACLManager
} from "@owl/core/src/core/a01-access-control/index.js";
import { AuthManager, TokenManager } from "@owl/core/src/core/a07-auth-session/index.js";
import { EventEmitter, SecurityLogger } from "@owl/core/src/core/a09-logging-monitoring/index.js";
import { HTTPClient } from "@owl/core/src/core/a08-data-integrity/HTTPClient.js";
import { RBACManager } from "@owl/core/src/core/a01-access-control/RBACManager.js";
import { SSRFGuard } from "@owl/core/src/core/a10-ssrf-defense/index.js";

const tokenManager = new TokenManager({ now: () => Date.now() });
tokenManager.setTokens({
  accessToken: "demo-access-token",
  refreshToken: "demo-refresh-token",
  expiresAt: Date.now() + 60 * 60 * 1000
});

const authManager = new AuthManager({ tokenManager });
authManager.setSession({ userId: "demo-user", roles: ["admin"] });

const rbacManager = new RBACManager();
rbacManager.defineRole("viewer", ["read:reports", "read:todos"]);
rbacManager.defineRole(
  "admin",
  ["read:reports", "read:health", "delete:reports", "write:todos", "delete:todos"],
  ["viewer"]
);

const aclManager = new ACLManager();
aclManager.setPolicy("reports", "read", "allow");
aclManager.setPolicy("reports", "delete", "deny");
aclManager.setPolicy("todos", "read", "allow");
aclManager.setPolicy("todos", "write", "allow");
aclManager.setPolicy("todos", "delete", "deny");

const csrfManager = {
  attach: (headers) => ({
    ...headers,
    "X-CSRF-Token": "demo-csrf-token"
  })
};

const events = new EventEmitter();
const logger = new SecurityLogger({
  sink: (entry) => {
    // Sample app keeps logs in console for demo visibility.
    console.log("[owl-demo]", entry);
  }
});

const apiClient = new HTTPClient({
  baseUrl: "https://api.example.com",
  csrfManager,
  tokenProvider: () => tokenManager.getAccessToken(),
  outboundRequestPolicy: new SSRFGuard(),
  fetchImpl: async (_url, options) => ({
    ok: true,
    status: 200,
    headers: options?.headers || {},
    clone: () => ({ json: async () => ({ status: "ok", source: "owl-sample" }) }),
    text: async () => "ok"
  })
});

export const security = {
  authManager,
  aclManager,
  rbacManager,
  tokenManager,
  apiClient,
  logger,
  events
};