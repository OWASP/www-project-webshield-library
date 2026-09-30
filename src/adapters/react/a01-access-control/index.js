import React from "react";
import { PermissionChecker } from "@owasp-webshield/core";
import { useAuth } from "../a07-auth-session/index.js";

export const ACLContext = React.createContext(null);
export const RBACContext = React.createContext(null);

export function ACLProvider({ aclManager, children }) {
	const value = React.useMemo(() => ({ aclManager }), [aclManager]);
	return React.createElement(ACLContext.Provider, { value }, children);
}

export function RBACProvider({ rbacManager, children }) {
	const value = React.useMemo(() => ({ rbacManager }), [rbacManager]);
	return React.createElement(RBACContext.Provider, { value }, children);
}

export function useACL() {
	const context = React.useContext(ACLContext);
	if (!context) {
		throw new Error("useACL must be used within ACLProvider");
	}
	return context.aclManager;
}

export function usePermission(action, resource) {
	const { session } = useAuth();
	const aclManager = useACL();
	const { rbacManager } = React.useContext(RBACContext) || {};

	const checker = React.useMemo(() => {
		if (!rbacManager || !aclManager) return null;
		return new PermissionChecker({ rbacManager, aclManager });
	}, [rbacManager, aclManager]);

	return React.useMemo(() => {
		const roles = Array.isArray(session?.roles) ? session.roles : [];
		if (roles.length === 0 || !checker) return { allowed: false, reason: "no_role" };
		// Allowed if any of the session's roles grants it; an ACL deny applies to every
		// role, so the first result already reports it.
		let result;
		for (const role of roles) {
			result = checker.check({ role, action, resource });
			if (result.allowed || result.reason === "acl_deny_override") return result;
		}
		return result;
	}, [session, checker, action, resource]);
}

export function PermissionGate({ action, resource, fallback = null, children }) {
	const permission = usePermission(action, resource);
	return permission.allowed ? React.createElement(React.Fragment, null, children) : fallback;
}