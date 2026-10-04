import { ACLManager, PermissionChecker, SecurityError, SecurityErrorCode } from "@owasp-webshield/core";

/**
 * Accepts a `PermissionChecker`, or anything holding an `rbacManager` (and
 * optionally an `aclManager`), such as the object `createOwlClient()` returns.
 */
export function toPermissionChecker(source) {
  if (source && typeof source.check === "function") return source;
  if (source?.rbacManager) {
    return new PermissionChecker({ rbacManager: source.rbacManager, aclManager: source.aclManager || new ACLManager() });
  }
  throw new SecurityError(
    SecurityErrorCode.MISCONFIGURATION,
    "Access control needs a PermissionChecker or an object with an rbacManager"
  );
}

/**
 * Checks every role of the session, the same rule `usePermission()` applies in
 * the React adapter: allowed if any role grants the permission, and an ACL deny
 * applies to every role.
 * @param {{session: {roles?: string[]} | null | undefined, action: string, resource: string}} request
 * @param {object} checkerSource see `toPermissionChecker()`
 * @returns {{allowed: boolean, reason: string}}
 */
export function checkPermission({ session, action, resource }, checkerSource) {
  const checker = toPermissionChecker(checkerSource);
  const roles = Array.isArray(session?.roles) ? session.roles : [];
  if (roles.length === 0) return { allowed: false, reason: "no_role" };

  let result;
  for (const role of roles) {
    result = checker.check({ role, action, resource });
    if (result.allowed || result.reason === "acl_deny_override") break;
  }
  return { allowed: result.allowed, reason: result.reason };
}

/**
 * Like `checkPermission()`, but throws `AUTH_REQUIRED` without a session and
 * `ACCESS_DENIED` when no role grants the permission.
 */
export function assertPermission({ session, action, resource }, checkerSource) {
  if (!session) {
    throw new SecurityError(SecurityErrorCode.AUTH_REQUIRED, "Authentication required");
  }
  const decision = checkPermission({ session, action, resource }, checkerSource);
  if (!decision.allowed) {
    throw new SecurityError(SecurityErrorCode.ACCESS_DENIED, `Not allowed to ${action} ${resource}`, {
      action,
      resource,
      reason: decision.reason
    });
  }
  return decision;
}
