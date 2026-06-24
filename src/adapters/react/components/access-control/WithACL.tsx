import React, { ReactNode } from 'react';
import { useACL } from '../../hooks/useACL';
import { ACLAction } from '../../types';

export interface WithACLProps {
  resource: string;
  permission: ACLAction;
  children: ReactNode;
  fallback?: ReactNode;
  onDenied?: () => void;
}

export const WithACL: React.FC<WithACLProps> = ({
  resource,
  permission,
  children,
  fallback = null,
  onDenied,
}) => {
  const { checkPermission } = useACL();

  if (!checkPermission(resource, permission)) {
    onDenied?.();
    return <>{fallback}</>;
  }

  return <>{children}</>;
};
