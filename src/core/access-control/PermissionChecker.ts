/**
 * PermissionChecker - Helper utility for checking permissions
 * Provides convenient static methods for permission validation
 */

import { RBACManager } from './RBACManager';
import { ACLManager } from './ACLManager';
import { ACLAction } from './types';

export class PermissionChecker {
  /**
   * Check if user has all required permissions using RBAC
   */
  static checkRBACPermissions(
    rbac: RBACManager,
    userId: string,
    requiredPermissions: string[]
  ): boolean {
    return rbac.hasAllPermissions(userId, requiredPermissions);
  }

  /**
   * Check if user has any of the required permissions using RBAC
   */
  static checkAnyRBACPermission(
    rbac: RBACManager,
    userId: string,
    permissions: string[]
  ): boolean {
    return rbac.hasAnyPermission(userId, permissions);
  }

  /**
   * Check if user has ACL access to a resource
   */
  static checkACLAccess(
    acl: ACLManager,
    resourceId: string,
    userId: string,
    action: ACLAction
  ): boolean {
    return acl.hasPermission(resourceId, userId, action);
  }

  /**
   * Check if user owns a resource
   */
  static isResourceOwner(
    acl: ACLManager,
    resourceId: string,
    userId: string
  ): boolean {
    return acl.isOwner(resourceId, userId);
  }

  /**
   * Validate access with combined RBAC and ACL
   */
  static validateCombinedAccess(
    rbac: RBACManager,
    acl: ACLManager,
    userId: string,
    resourceId: string,
    requiredRBACPermissions: string[],
    requiredACLAction: ACLAction
  ): boolean {
    // Check RBAC permissions
    const hasRBACAccess = rbac.hasAllPermissions(
      userId,
      requiredRBACPermissions
    );

    // Check ACL permissions
    const hasACLAccess = acl.hasPermission(
      resourceId,
      userId,
      requiredACLAction
    );

    return hasRBACAccess && hasACLAccess;
  }

  /**
   * Get summary of user access
   */
  static getUserAccessSummary(
    rbac: RBACManager,
    acl: ACLManager,
    userId: string
  ) {
    return {
      roles: rbac.getUserRoles(userId),
      permissions: Array.from(rbac.getUserPermissions(userId)),
      aclResources: acl.getUserAccessibleResources(userId),
    };
  }

  /**
   * Check if user has admin role
   */
  static isAdmin(rbac: RBACManager, userId: string, adminRoleId: string = 'admin'): boolean {
    return rbac.hasRole(userId, adminRoleId);
  }

  /**
   * Check if user can perform action on resource
   */
  static canPerformAction(
    acl: ACLManager,
    userId: string,
    resourceId: string,
    action: ACLAction
  ): { allowed: boolean; reason?: string } {
    const resource = acl.getResource(resourceId);
    if (!resource) {
      return { allowed: false, reason: 'Resource not found' };
    }

    if (acl.isOwner(resourceId, userId)) {
      return { allowed: true, reason: 'User is resource owner' };
    }

    if (acl.hasPermission(resourceId, userId, action)) {
      return { allowed: true, reason: 'User has explicit permission' };
    }

    if (resource.isPublic && action === 'read') {
      return { allowed: true, reason: 'Resource is public' };
    }

    return { allowed: false, reason: 'No permission' };
  }
}
