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
 *   authManager?: import("@owasp-webshield/core").AuthManager,
 *   aclManager?: import("@owasp-webshield/core").ACLManager,
 *   rbacManager?: import("@owasp-webshield/core").RBACManager,
 *   logger?: import("@owasp-webshield/core").SecurityLogger,
 *   events?: import("@owasp-webshield/core").EventEmitter,
 *   children?: React.ReactNode
 * }} props
 */
export function OwlProvider({ client, authManager, aclManager, rbacManager, logger, events, children }: {
    client?: {
        authManager?: any;
        aclManager?: any;
        rbacManager?: any;
        logger?: any;
        events?: any;
    };
    authManager?: import("@owasp-webshield/core").AuthManager;
    aclManager?: import("@owasp-webshield/core").ACLManager;
    rbacManager?: import("@owasp-webshield/core").RBACManager;
    logger?: import("@owasp-webshield/core").SecurityLogger;
    events?: import("@owasp-webshield/core").EventEmitter;
    children?: React.ReactNode;
}): any;
import React from "react";
