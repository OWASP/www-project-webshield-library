import { useCallback } from 'react';
import { useRBAC } from './useRBAC';
import { useACL } from './useACL';
import { ACLAction } from '../types';

export interface UsePermissionOptions {
  /** RBAC role(s) that grant access */
  roles?: string | string[];
  /** RBAC permission(s) required */
  permissions?: string | string[];
  /** ACL resource id */
  resource?: string;
  /** ACL action on the resource */
  action?: ACLAction;
  /** When true, all permissions must match (default: any) */
  requireAll?: boolean;
}

export interface UsePermissionResult {
  allowed: boolean;
  checkRole(role: string | string[]): boolean;
  checkPermission(permission: string | string[]): boolean;
  checkACL(resource: string, action: ACLAction): boolean;
}

export function usePermission(opts: UsePermissionOptions = {}): UsePermissionResult {
  const { hasRole, hasPermission, hasAllPermissions, hasAnyPermission } = useRBAC();
  const { checkPermission: aclCheck } = useACL();

  const checkRole = useCallback(
    (role: string | string[]) => hasRole(role),
    [hasRole]
  );

  const checkPermission = useCallback(
    (permission: string | string[]) => hasPermission(permission),
    [hasPermission]
  );

  const checkACL = useCallback(
    (resource: string, action: ACLAction) => aclCheck(resource, action),
    [aclCheck]
  );

  // Evaluate composite allowed flag from opts
  let allowed = true;

  if (opts.roles !== undefined) {
    allowed = allowed && hasRole(opts.roles);
  }

  if (opts.permissions !== undefined) {
    const permsArray = Array.isArray(opts.permissions)
      ? opts.permissions
      : [opts.permissions];
    allowed =
      allowed &&
      (opts.requireAll ? hasAllPermissions(permsArray) : hasAnyPermission(permsArray));
  }

  if (opts.resource !== undefined && opts.action !== undefined) {
    allowed = allowed && aclCheck(opts.resource, opts.action);
  }

  return { allowed, checkRole, checkPermission, checkACL };
}
