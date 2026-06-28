import React from "react";
import { PermissionChecker } from "../../../core/a01-access-control/PermissionChecker.js";
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
		const role = session?.roles?.[0];
		if (!role || !checker) return { allowed: false, reason: "no_role" };
		return checker.check({ role, action, resource });
	}, [session, checker, action, resource]);
}

export function PermissionGate({ action, resource, fallback = null, children }) {
	const permission = usePermission(action, resource);
	return permission.allowed ? React.createElement(React.Fragment, null, children) : fallback;
}