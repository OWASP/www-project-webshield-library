/**
 * Access Control Types
 * Defines ACL and RBAC interfaces
 */

/**
 * ACL action types
 */
export type ACLAction = 'read' | 'write' | 'delete' | 'admin' | 'share';

/**
 * ACL permission entry
 */
export interface ACLPermission {
  resourceId: string;
  userId: string;
  action: ACLAction;
  grantedBy: string;
  grantedAt: number;
  expiresAt?: number;
}

/**
 * ACL resource
 */
export interface ACLResource {
  id: string;
  name: string;
  ownerId: string;
  createdAt: number;
  isPublic: boolean;
  metadata?: Record<string, any>;
}

/**
 * RBAC role definition
 */
export interface RBACRole {
  id: string;
  name: string;
  permissions: string[];
  hierarchy?: number;
  description?: string;
}

/**
 * RBAC user role assignment
 */
export interface RBACUserRole {
  userId: string;
  roleId: string;
  assignedAt: number;
  assignedBy: string;
  expiresAt?: number;
}
