import React, { ReactNode } from 'react';
import { useRBAC } from '../../hooks/useRBAC';

export interface WithRBACProps {
  roles?: string | string[];
  permissions?: string | string[];
  /** When true, ALL listed permissions are required (default: any) */
  requireAll?: boolean;
  children: ReactNode;
  fallback?: ReactNode;
  onDenied?: () => void;
}

export const WithRBAC: React.FC<WithRBACProps> = ({
  roles,
  permissions,
  requireAll = false,
  children,
  fallback = null,
  onDenied,
}) => {
  const { hasRole, hasAllPermissions, hasAnyPermission, hasPermission } = useRBAC();

  if (roles !== undefined && !hasRole(roles)) {
    onDenied?.();
    return <>{fallback}</>;
  }

  if (permissions !== undefined) {
    const permsArray = Array.isArray(permissions) ? permissions : [permissions];
    const ok = requireAll
      ? hasAllPermissions(permsArray)
      : hasAnyPermission(permsArray) || hasPermission(permissions);
    if (!ok) {
      onDenied?.();
      return <>{fallback}</>;
    }
  }

  return <>{children}</>;
};
