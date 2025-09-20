import React from "react";
import { useACL } from "../hooks/useACL";

export interface WithACLProps {
  roleId: string;
  action: string;
  resource: string;
  context?: Record<string, unknown>;
  fallback?: React.ReactNode;
  children: React.ReactNode;
}

export const WithACL: React.FC<WithACLProps> = ({
  children,
  roleId,
  action,
  resource,
  context = {},
  fallback = null,
}) => {
  const { checkPermission } = useACL();
  const [hasAccess, setHasAccess] = React.useState<boolean>(false);

  React.useEffect(() => {
    const checkAccess = async () => {
      try {
        const result = await checkPermission(roleId, action, resource, context);
        setHasAccess(result);
      } catch (error) {
        console.error("Error checking permission:", error);
        setHasAccess(false);
      }
    };

    checkAccess();
  }, [checkPermission, roleId, action, resource, context]);

  if (!hasAccess) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
};

export function withACL<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  options: Omit<WithACLProps, "children">
): React.FC<P> {
  return function WithACLWrapper(props: P) {
    return (
      <WithACL {...options}>
        <WrappedComponent {...props} />
      </WithACL>
    );
  };
}
