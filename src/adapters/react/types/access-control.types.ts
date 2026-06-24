export type ACLAction = 'read' | 'write' | 'delete' | 'admin' | 'share';

export interface ACLPermission {
  resourceId: string;
  userId: string;
  actions: ACLAction[];
  grantedBy?: string;
  grantedAt?: Date;
  expiresAt?: Date;
}

export interface ACLResource {
  id: string;
  type: string;
  owner: string;
  permissions: ACLPermission[];
  isPublic: boolean;
}

export interface ACLContextType {
  checkPermission(resourceId: string, action: ACLAction): boolean;
  hasAccess(resourceId: string, userId: string, action: ACLAction): boolean;
  canModify(resourceId: string): boolean;
  canDelete(resourceId: string): boolean;
  canShare(resourceId: string): boolean;
  grantPermission(resourceId: string, userId: string, actions: ACLAction[]): Promise<void>;
  revokePermission(resourceId: string, userId: string): Promise<void>;
  getResourcePermissions(resourceId: string): ACLPermission[];
}

export interface RBACRole {
  id: string;
  name: string;
  description?: string;
  permissions: string[];
  hierarchy?: number;
}

export interface RBACContextType {
  currentRoles: RBACRole[];
  hasRole(role: string | string[]): boolean;
  hasPermission(permission: string | string[]): boolean;
  hasAllPermissions(permissions: string[]): boolean;
  hasAnyPermission(permissions: string[]): boolean;
}
