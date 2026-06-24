import React, { createContext, useMemo, ReactNode } from 'react';
import { RBACContextType } from '../types';
import { useAuth } from '../hooks/useAuth';

export const RBACContext = createContext<RBACContextType | undefined>(undefined);

export interface RBACProviderProps {
  children: ReactNode;
}

export const RBACProvider: React.FC<RBACProviderProps> = ({ children }) => {
  const { user } = useAuth();

  const value: RBACContextType = useMemo(
    () => ({
      currentRoles: user?.roles ?? [],

      hasRole: (role: string | string[]): boolean => {
        if (!user) return false;
        const roles = Array.isArray(role) ? role : [role];
        return roles.some((r) => user.roles.some((ur) => ur.name === r));
      },

      hasPermission: (permission: string | string[]): boolean => {
        if (!user) return false;
        const perms = Array.isArray(permission) ? permission : [permission];
        return perms.some((p) => user.permissions.includes(p));
      },

      hasAllPermissions: (permissions: string[]): boolean => {
        if (!user) return false;
        return permissions.every((p) => user.permissions.includes(p));
      },

      hasAnyPermission: (permissions: string[]): boolean => {
        if (!user) return false;
        return permissions.some((p) => user.permissions.includes(p));
      },
    }),
    [user]
  );

  return <RBACContext.Provider value={value}>{children}</RBACContext.Provider>;
};
