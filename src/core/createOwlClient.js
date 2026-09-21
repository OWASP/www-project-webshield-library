import { ACLManager } from "./a01-access-control/ACLManager.js";
import { RBACManager } from "./a01-access-control/RBACManager.js";
import { AuthManager } from "./a07-auth-session/AuthManager.js";
import { TokenManager } from "./a07-auth-session/TokenManager.js";
import { EventEmitter } from "./a09-logging-monitoring/EventEmitter.js";
import { SecurityLogger } from "./a09-logging-monitoring/SecurityLogger.js";

/**
 * Builds and wires the manager set that `<OwlProvider>` (from
 * `@owasp-webshield/react`) needs — `TokenManager`, `AuthManager`,
 * `RBACManager`, `ACLManager`, `EventEmitter`, and `SecurityLogger` — from one
 * declarative config object, instead of constructing and threading each one
 * by hand. Every returned manager is the same real class you'd get by
 * constructing it directly, so anything not covered by this config shape
 * (interceptors, a custom storage adapter, etc.) can still be set via its
 * normal API on the returned instance.
 *
 * @param {{
 *   roles?: Record<string, {permissions?: string[], inherits?: string[]}>,
 *   acl?: Array<{resource: string, action: string, effect: "allow"|"deny"}>,
 *   token?: ConstructorParameters<typeof TokenManager>[0],
 *   auth?: Omit<ConstructorParameters<typeof AuthManager>[0], "tokenManager">,
 *   logger?: ConstructorParameters<typeof SecurityLogger>[0]
 * }} [config]
 */
export function createOwlClient(config = {}) {
  const tokenManager = new TokenManager(config.token);
  const authManager = new AuthManager({ tokenManager, ...config.auth });

  const rbacManager = new RBACManager();
  for (const [role, definition] of Object.entries(config.roles || {})) {
    rbacManager.defineRole(role, definition.permissions || [], definition.inherits || []);
  }

  const aclManager = new ACLManager();
  for (const { resource, action, effect } of config.acl || []) {
    aclManager.setPolicy(resource, action, effect);
  }

  const events = new EventEmitter();
  const logger = new SecurityLogger(config.logger);

  return { tokenManager, authManager, rbacManager, aclManager, events, logger };
}
