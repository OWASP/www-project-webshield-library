import React from "react";
import { withACL } from "./WithACL";
import { useACL } from "../hooks/useACL";

interface ProtectedRouteProps {
  roleId: string;
  path: string;
  fallback?: React.ReactNode;
  children: React.ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  roleId,
  path,
  children,
  fallback = null,
}) => {
  return (
    <WithACL
      roleId={roleId}
      action="access"
      resource={`route:${path}`}
      fallback={fallback}
    >
      {children}
    </WithACL>
  );
};

export function withProtectedRoute<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  options: Omit<ProtectedRouteProps, "children">
): React.FC<P> {
  return function WithProtectedRouteWrapper(props: P) {
    return (
      <ProtectedRoute {...options}>
        <WrappedComponent {...props} />
      </ProtectedRoute>
    );
  };
}
