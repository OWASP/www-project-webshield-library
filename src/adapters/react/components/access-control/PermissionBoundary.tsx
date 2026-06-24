import React, { ReactNode } from 'react';
import { usePermission, UsePermissionOptions } from '../../hooks/usePermission';

export interface PermissionBoundaryProps extends UsePermissionOptions {
  children: ReactNode;
  fallback?: ReactNode;
  onDenied?: () => void;
}

/**
 * Combines RBAC role/permission checks and ACL resource checks in a single
 * boundary component.
 */
export const PermissionBoundary: React.FC<PermissionBoundaryProps> = ({
  children,
  fallback = null,
  onDenied,
  ...opts
}) => {
  const { allowed } = usePermission(opts);

  if (!allowed) {
    onDenied?.();
    return <>{fallback}</>;
  }

  return <>{children}</>;
};
