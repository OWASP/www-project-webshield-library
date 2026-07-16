import {
  ACLManager,
  AuthManager,
  EventEmitter,
  RBACManager,
  SecurityLogger,
  TokenManager
} from "../../../src/index.js";

const tokenManager = new TokenManager({
  now: () => Date.now(),
  onRefresh: async (refreshToken) => ({
    accessToken: `rotated-${refreshToken}`,
    refreshToken,
    expiresAt: Date.now() + 60_000
  })
});

tokenManager.setTokens({
  accessToken: "demo-access-token",
  refreshToken: "demo-refresh-token",
  expiresAt: Date.now() + 30 * 60 * 1000
});

const authManager = new AuthManager({ tokenManager });
authManager.setSession({ userId: "demo-user", roles: ["editor"] });

const aclManager = new ACLManager();
aclManager.setPolicy("articles", "read", "allow");
aclManager.setPolicy("articles", "update", "allow");
aclManager.setPolicy("articles", "delete", "deny");

const rbacManager = new RBACManager();
rbacManager.defineRole("viewer", ["read:articles"]);
rbacManager.defineRole("editor", ["update:articles"], ["viewer"]);

const events = new EventEmitter();
const logger = new SecurityLogger({
  sink: (entry) => {
    console.log("[react-demo]", entry);
  }
});

export const security = {
  tokenManager,
  authManager,
  aclManager,
  rbacManager,
  events,
  logger
};