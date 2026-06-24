import React, {
  createContext,
  useState,
  useCallback,
  ReactNode,
} from 'react';
import { ACLContextType, ACLPermission, ACLAction } from '../types';
import { useAuth } from '../hooks/useAuth';

export const ACLContext = createContext<ACLContextType | undefined>(undefined);

export interface ACLProviderProps {
  children: ReactNode;
  apiBaseUrl: string;
}

export const ACLProvider: React.FC<ACLProviderProps> = ({
  children,
  apiBaseUrl,
}) => {
  const { user, token } = useAuth();
  const [permissions, setPermissions] = useState<Map<string, ACLPermission[]>>(
    new Map()
  );

  const checkPermission = useCallback(
    (resourceId: string, action: ACLAction): boolean => {
      if (!user) return false;
      const resourcePerms = permissions.get(resourceId) ?? [];
      const userPerm = resourcePerms.find((p) => p.userId === user.id);
      if (!userPerm) return false;
      if (userPerm.expiresAt && new Date() > new Date(userPerm.expiresAt)) {
        return false;
      }
      return userPerm.actions.includes(action);
    },
    [user, permissions]
  );

  const hasAccess = useCallback(
    (resourceId: string, userId: string, action: ACLAction): boolean => {
      const resourcePerms = permissions.get(resourceId) ?? [];
      const perm = resourcePerms.find((p) => p.userId === userId);
      if (!perm) return false;
      if (perm.expiresAt && new Date() > new Date(perm.expiresAt)) return false;
      return perm.actions.includes(action);
    },
    [permissions]
  );

  const canModify = useCallback(
    (resourceId: string) => checkPermission(resourceId, 'write'),
    [checkPermission]
  );

  const canDelete = useCallback(
    (resourceId: string) => checkPermission(resourceId, 'delete'),
    [checkPermission]
  );

  const canShare = useCallback(
    (resourceId: string) => checkPermission(resourceId, 'share'),
    [checkPermission]
  );

  const grantPermission = useCallback(
    async (resourceId: string, userId: string, actions: ACLAction[]): Promise<void> => {
      if (!token) throw new Error('Not authenticated');

      const response = await fetch(
        `${apiBaseUrl}/acl/resources/${resourceId}/permissions`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token.accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ userId, actions }),
        }
      );

      if (!response.ok) {
        throw new Error('Failed to grant permission');
      }

      const newPerm: ACLPermission = await response.json();
      setPermissions((prev) => {
        const next = new Map(prev);
        const existing = next.get(resourceId) ?? [];
        // Replace if same userId, otherwise append
        const filtered = existing.filter((p) => p.userId !== userId);
        next.set(resourceId, [...filtered, newPerm]);
        return next;
      });
    },
    [apiBaseUrl, token]
  );

  const revokePermission = useCallback(
    async (resourceId: string, userId: string): Promise<void> => {
      if (!token) throw new Error('Not authenticated');

      const response = await fetch(
        `${apiBaseUrl}/acl/resources/${resourceId}/permissions/${userId}`,
        {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token.accessToken}` },
        }
      );

      if (!response.ok) {
        throw new Error('Failed to revoke permission');
      }

      setPermissions((prev) => {
        const next = new Map(prev);
        const existing = next.get(resourceId) ?? [];
        next.set(resourceId, existing.filter((p) => p.userId !== userId));
        return next;
      });
    },
    [apiBaseUrl, token]
  );

  const getResourcePermissions = useCallback(
    (resourceId: string): ACLPermission[] => permissions.get(resourceId) ?? [],
    [permissions]
  );

  const value: ACLContextType = {
    checkPermission,
    hasAccess,
    canModify,
    canDelete,
    canShare,
    grantPermission,
    revokePermission,
    getResourcePermissions,
  };

  return <ACLContext.Provider value={value}>{children}</ACLContext.Provider>;
};
