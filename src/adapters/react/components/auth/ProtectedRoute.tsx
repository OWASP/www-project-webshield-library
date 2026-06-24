import React, { ReactNode } from 'react';
import { useAuth } from '../../hooks/useAuth';

export interface ProtectedRouteProps {
  children: ReactNode;
  fallback?: ReactNode;
  requiredRoles?: string[];
  requiredPermissions?: string[];
  onUnauthorized?: () => void;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  fallback = <div>Please log in to access this page.</div>,
  requiredRoles,
  requiredPermissions,
  onUnauthorized,
}) => {
  const { isAuthenticated, isLoading, user } = useAuth();

  if (isLoading) {
    return <div aria-busy="true">Loading...</div>;
  }

  if (!isAuthenticated) {
    onUnauthorized?.();
    return <>{fallback}</>;
  }

  if (requiredRoles && user) {
    const hasRequiredRole = requiredRoles.some((role) =>
      user.roles.some((ur) => ur.name === role)
    );
    if (!hasRequiredRole) {
      onUnauthorized?.();
      return <>{fallback}</>;
    }
  }

  if (requiredPermissions && user) {
    const hasAll = requiredPermissions.every((perm) =>
      user.permissions.includes(perm)
    );
    if (!hasAll) {
      onUnauthorized?.();
      return <>{fallback}</>;
    }
  }

  return <>{children}</>;
};
