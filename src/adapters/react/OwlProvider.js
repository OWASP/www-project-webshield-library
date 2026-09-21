import React from "react";
import { ACLProvider, RBACProvider } from "./a01-access-control/index.js";
import { AuthProvider } from "./a07-auth-session/index.js";
import { SecurityProvider } from "./a09-logging-monitoring/index.js";

/**
 * Composes `SecurityProvider` > `AuthProvider` > `ACLProvider` > `RBACProvider`
 * into one component, so wiring the security context into a tree is one prop
 * object instead of four nested providers.
 *
 * Accepts either the object returned by `createOwlClient()` (`client` prop)
 * or the individual managers directly — the latter override anything from
 * `client` with the same name, so you can build most of the client with
 * `createOwlClient()` and still swap one manager in by hand if needed.
 *
 * @param {{
 *   client?: {authManager?, aclManager?, rbacManager?, logger?, events?},
 *   authManager?: import("../../core/a07-auth-session/AuthManager.js").AuthManager,
 *   aclManager?: import("../../core/a01-access-control/ACLManager.js").ACLManager,
 *   rbacManager?: import("../../core/a01-access-control/RBACManager.js").RBACManager,
 *   logger?: import("../../core/a09-logging-monitoring/SecurityLogger.js").SecurityLogger,
 *   events?: import("../../core/a09-logging-monitoring/EventEmitter.js").EventEmitter,
 *   children?: React.ReactNode
 * }} props
 */
export function OwlProvider({ client = {}, authManager, aclManager, rbacManager, logger, events, children }) {
  const resolvedAuthManager = authManager ?? client.authManager;
  const resolvedAclManager = aclManager ?? client.aclManager;
  const resolvedRbacManager = rbacManager ?? client.rbacManager;
  const resolvedLogger = logger ?? client.logger;
  const resolvedEvents = events ?? client.events;

  return React.createElement(
    SecurityProvider,
    { logger: resolvedLogger, events: resolvedEvents },
    React.createElement(
      AuthProvider,
      { authManager: resolvedAuthManager },
      React.createElement(
        ACLProvider,
        { aclManager: resolvedAclManager },
        React.createElement(RBACProvider, { rbacManager: resolvedRbacManager }, children)
      )
    )
  );
}
