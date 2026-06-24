import React, { ReactNode, useEffect } from 'react';
import { useAuth } from '../../hooks/useAuth';

export interface AuthGuardProps {
  children: ReactNode;
  /** Called when user is not authenticated; use to redirect */
  onUnauthenticated?: () => void;
  /** Called when user lacks required role/permission */
  onForbidden?: () => void;
  requiredRoles?: string[];
  requiredPermissions?: string[];
  loadingComponent?: ReactNode;
  forbiddenComponent?: ReactNode;
  unauthenticatedComponent?: ReactNode;
}

export const AuthGuard: React.FC<AuthGuardProps> = ({
  children,
  onUnauthenticated,
  onForbidden,
  requiredRoles,
  requiredPermissions,
  loadingComponent = <div aria-busy="true">Loading...</div>,
  forbiddenComponent = <div>Access Denied</div>,
  unauthenticatedComponent = <div>Please log in</div>,
}) => {
  const { isAuthenticated, isLoading, user } = useAuth();

  const isRoleAllowed =
    !requiredRoles ||
    !user ||
    requiredRoles.some((role) => user.roles.some((ur) => ur.name === role));

  const isPermissionAllowed =
    !requiredPermissions ||
    !user ||
    requiredPermissions.every((p) => user.permissions.includes(p));

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      onUnauthenticated?.();
    }
  }, [isLoading, isAuthenticated, onUnauthenticated]);

  useEffect(() => {
    if (!isLoading && isAuthenticated && (!isRoleAllowed || !isPermissionAllowed)) {
      onForbidden?.();
    }
  }, [isLoading, isAuthenticated, isRoleAllowed, isPermissionAllowed, onForbidden]);

  if (isLoading) return <>{loadingComponent}</>;
  if (!isAuthenticated) return <>{unauthenticatedComponent}</>;
  if (!isRoleAllowed || !isPermissionAllowed) return <>{forbiddenComponent}</>;

  return <>{children}</>;
};
