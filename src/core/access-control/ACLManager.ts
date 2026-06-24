/**
 * ACLManager - Access Control List Manager
 * Manages fine-grained access control to specific resources
 */

import { ACLPermission, ACLResource, ACLAction } from './types';
import { EventEmitter } from '../events/EventEmitter';

export class ACLManager {
  private resources: Map<string, ACLResource> = new Map();
  private permissions: Map<string, ACLPermission[]> = new Map();
  private events: EventEmitter;

  constructor() {
    this.events = new EventEmitter();
  }

  /**
   * Create a new resource
   */
  createResource(
    id: string,
    name: string,
    ownerId: string,
    isPublic: boolean = false
  ): ACLResource {
    const resource: ACLResource = {
      id,
      name,
      ownerId,
      createdAt: Date.now(),
      isPublic,
    };

    this.resources.set(id, resource);
    this.events.emit('acl:resource:created', { resource });

    return resource;
  }

  /**
   * Delete a resource
   */
  deleteResource(resourceId: string): boolean {
    const deleted = this.resources.delete(resourceId);
    if (deleted) {
      this.permissions.delete(resourceId);
      this.events.emit('acl:resource:deleted', { resourceId });
    }
    return deleted;
  }

  /**
   * Get a resource
   */
  getResource(resourceId: string): ACLResource | undefined {
    return this.resources.get(resourceId);
  }

  /**
   * Grant permission to user for a resource
   */
  grantPermission(
    resourceId: string,
    userId: string,
    action: ACLAction,
    grantedBy: string,
    expiresAt?: number
  ): void {
    const resource = this.resources.get(resourceId);
    if (!resource) {
      throw new Error(`Resource "${resourceId}" does not exist`);
    }

    const permission: ACLPermission = {
      resourceId,
      userId,
      action,
      grantedBy,
      grantedAt: Date.now(),
      expiresAt,
    };

    const permissionsList = this.permissions.get(resourceId) ?? [];
    permissionsList.push(permission);
    this.permissions.set(resourceId, permissionsList);

    this.events.emit('acl:permission:granted', { resourceId, userId, action, permission });
  }

  /**
   * Revoke permission from user for a resource
   */
  revokePermission(
    resourceId: string,
    userId: string,
    action?: ACLAction
  ): boolean {
    const permissionsList = this.permissions.get(resourceId);
    if (!permissionsList) {
      return false;
    }

    const initialLength = permissionsList.length;
    const filtered = permissionsList.filter(
      (p) => !(p.userId === userId && (!action || p.action === action))
    );

    if (filtered.length < initialLength) {
      if (filtered.length === 0) {
        this.permissions.delete(resourceId);
      } else {
        this.permissions.set(resourceId, filtered);
      }
      this.events.emit('acl:permission:revoked', { resourceId, userId, action });
      return true;
    }

    return false;
  }

  /**
   * Check if user has permission for a resource
   */
  hasPermission(
    resourceId: string,
    userId: string,
    action: ACLAction
  ): boolean {
    const resource = this.resources.get(resourceId);
    if (!resource) {
      return false;
    }

    // Owner always has permission
    if (resource.ownerId === userId) {
      return true;
    }

    // Check if resource is public and action is read
    if (resource.isPublic && action === 'read') {
      return true;
    }

    const permissionsList = this.permissions.get(resourceId);
    if (!permissionsList) {
      return false;
    }

    return permissionsList.some((p) => {
      if (p.userId !== userId || p.action !== action) {
        return false;
      }

      // Check if permission has expired
      if (p.expiresAt && p.expiresAt < Date.now()) {
        return false;
      }

      return true;
    });
  }

  /**
   * Check if user is the owner of a resource
   */
  isOwner(resourceId: string, userId: string): boolean {
    const resource = this.resources.get(resourceId);
    return resource?.ownerId === userId ?? false;
  }

  /**
   * Get all permissions for a resource
   */
  getResourcePermissions(resourceId: string): ACLPermission[] {
    return (this.permissions.get(resourceId) ?? []).filter(
      (p) => !p.expiresAt || p.expiresAt >= Date.now()
    );
  }

  /**
   * Get all permissions for a user on a resource
   */
  getUserResourcePermissions(
    resourceId: string,
    userId: string
  ): ACLPermission[] {
    return this.getResourcePermissions(resourceId).filter(
      (p) => p.userId === userId
    );
  }

  /**
   * Get all resources a user has access to with a specific action
   */
  getUserAccessibleResources(userId: string, action?: ACLAction): ACLResource[] {
    const resources: ACLResource[] = [];

    this.resources.forEach((resource) => {
      // Owner always has access
      if (resource.ownerId === userId) {
        resources.push(resource);
        return;
      }

      // Check public resources for read action
      if (resource.isPublic && (!action || action === 'read')) {
        resources.push(resource);
        return;
      }

      // Check permissions
      const permissionsList = this.permissions.get(resource.id);
      if (permissionsList) {
        const hasAccess = permissionsList.some((p) => {
          if (p.userId !== userId) {
            return false;
          }
          if (action && p.action !== action) {
            return false;
          }
          if (p.expiresAt && p.expiresAt < Date.now()) {
            return false;
          }
          return true;
        });

        if (hasAccess) {
          resources.push(resource);
        }
      }
    });

    return resources;
  }

  /**
   * Grant permission to transfer resource ownership
   */
  shareResource(
    resourceId: string,
    grantToUserId: string,
    grantedBy: string
  ): void {
    const resource = this.resources.get(resourceId);
    if (!resource) {
      throw new Error(`Resource "${resourceId}" does not exist`);
    }

    this.grantPermission(resourceId, grantToUserId, 'admin', grantedBy);
    this.events.emit('acl:resource:shared', {
      resourceId,
      grantToUserId,
      grantedBy,
    });
  }

  /**
   * Transfer resource ownership
   */
  transferOwnership(resourceId: string, newOwnerId: string): boolean {
    const resource = this.resources.get(resourceId);
    if (!resource) {
      return false;
    }

    resource.ownerId = newOwnerId;
    this.events.emit('acl:resource:ownership:transferred', {
      resourceId,
      newOwnerId,
    });

    return true;
  }

  /**
   * Check if permission is expired
   */
  isPermissionExpired(permission: ACLPermission): boolean {
    if (!permission.expiresAt) {
      return false;
    }
    return permission.expiresAt < Date.now();
  }

  /**
   * Clear expired permissions
   */
  clearExpiredPermissions(): void {
    const now = Date.now();

    this.permissions.forEach((permList, resourceId) => {
      const filtered = permList.filter((p) => !p.expiresAt || p.expiresAt >= now);
      if (filtered.length < permList.length) {
        if (filtered.length === 0) {
          this.permissions.delete(resourceId);
        } else {
          this.permissions.set(resourceId, filtered);
        }
      }
    });

    this.events.emit('acl:expired:cleared');
  }

  /**
   * Subscribe to ACL events
   */
  on(event: string, listener: (...args: any[]) => void): void {
    this.events.on(event, listener);
  }

  /**
   * Unsubscribe from ACL events
   */
  off(event: string, listener: (...args: any[]) => void): void {
    this.events.off(event, listener);
  }
}
