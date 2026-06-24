import React, { ComponentType } from 'react';
import { useAuth } from '../../hooks/useAuth';

export interface WithAuthProps {
  fallback?: React.ReactNode;
  requiredRoles?: string[];
  requiredPermissions?: string[];
}

/**
 * Higher-order component that wraps a component with authentication protection.
 */
export function withAuth<P extends object>(
  WrappedComponent: ComponentType<P>,
  options: WithAuthProps = {}
): React.FC<P> {
  const {
    fallback = <div>Unauthorized</div>,
    requiredRoles,
    requiredPermissions,
  } = options;

  const WithAuthComponent: React.FC<P> = (props) => {
    const { isAuthenticated, isLoading, user } = useAuth();

    if (isLoading) return <div aria-busy="true">Loading...</div>;
    if (!isAuthenticated) return <>{fallback}</>;

    if (requiredRoles && user) {
      const ok = requiredRoles.some((role) =>
        user.roles.some((ur) => ur.name === role)
      );
      if (!ok) return <>{fallback}</>;
    }

    if (requiredPermissions && user) {
      const ok = requiredPermissions.every((p) => user.permissions.includes(p));
      if (!ok) return <>{fallback}</>;
    }

    return <WrappedComponent {...props} />;
  };

  WithAuthComponent.displayName = `WithAuth(${
    WrappedComponent.displayName ?? WrappedComponent.name ?? 'Component'
  })`;

  return WithAuthComponent;
}
