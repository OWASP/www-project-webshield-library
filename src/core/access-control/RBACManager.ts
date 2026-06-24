/**
 * RBACManager - Role-Based Access Control Manager
 * Manages roles, permissions, and user role assignments
 */

import { RBACRole, RBACUserRole } from './types';
import { EventEmitter } from '../events/EventEmitter';

export class RBACManager {
  private roles: Map<string, RBACRole> = new Map();
  private userRoles: Map<string, RBACUserRole[]> = new Map();
  private events: EventEmitter;

  constructor() {
    this.events = new EventEmitter();
  }

  /**
   * Add a role to the system
   */
  addRole(role: RBACRole): void {
    this.roles.set(role.id, role);
    this.events.emit('rbac:role:added', { role });
  }

  /**
   * Remove a role from the system
   */
  removeRole(roleId: string): boolean {
    const removed = this.roles.delete(roleId);
    if (removed) {
      this.events.emit('rbac:role:removed', { roleId });
    }
    return removed;
  }

  /**
   * Get a role by ID
   */
  getRole(roleId: string): RBACRole | undefined {
    return this.roles.get(roleId);
  }

  /**
   * Get all roles
   */
  getAllRoles(): RBACRole[] {
    return Array.from(this.roles.values());
  }

  /**
   * Assign a role to a user
   */
  assignRoleToUser(
    userId: string,
    roleId: string,
    assignedBy: string,
    expiresAt?: number
  ): void {
    if (!this.roles.has(roleId)) {
      throw new Error(`Role "${roleId}" does not exist`);
    }

    const userRolesList = this.userRoles.get(userId) ?? [];
    const assignment: RBACUserRole = {
      userId,
      roleId,
      assignedAt: Date.now(),
      assignedBy,
      expiresAt,
    };

    userRolesList.push(assignment);
    this.userRoles.set(userId, userRolesList);

    this.events.emit('rbac:user:role:assigned', { userId, roleId, assignment });
  }

  /**
   * Remove a role from a user
   */
  removeRoleFromUser(userId: string, roleId: string): boolean {
    const userRolesList = this.userRoles.get(userId);
    if (!userRolesList) {
      return false;
    }

    const initialLength = userRolesList.length;
    const filtered = userRolesList.filter((r) => r.roleId !== roleId);

    if (filtered.length < initialLength) {
      this.userRoles.set(userId, filtered);
      this.events.emit('rbac:user:role:removed', { userId, roleId });
      return true;
    }

    return false;
  }

  /**
   * Check if user has a specific role
   */
  hasRole(userId: string, roleId: string): boolean {
    const userRolesList = this.userRoles.get(userId);
    if (!userRolesList) {
      return false;
    }

    return userRolesList.some((r) => {
      if (r.roleId !== roleId) {
        return false;
      }

      // Check if role assignment has expired
      if (r.expiresAt && r.expiresAt < Date.now()) {
        return false;
      }

      return true;
    });
  }

  /**
   * Check if user has specific permission
   */
  hasPermission(userId: string, permission: string): boolean {
    const userRolesList = this.userRoles.get(userId);
    if (!userRolesList) {
      return false;
    }

    return userRolesList.some((r) => {
      // Check if role assignment has expired
      if (r.expiresAt && r.expiresAt < Date.now()) {
        return false;
      }

      const role = this.roles.get(r.roleId);
      return role?.permissions.includes(permission) ?? false;
    });
  }

  /**
   * Check if user has all permissions
   */
  hasAllPermissions(userId: string, permissions: string[]): boolean {
    return permissions.every((permission) => this.hasPermission(userId, permission));
  }

  /**
   * Check if user has any of the permissions
   */
  hasAnyPermission(userId: string, permissions: string[]): boolean {
    return permissions.some((permission) => this.hasPermission(userId, permission));
  }

  /**
   * Get all permissions for a user
   */
  getUserPermissions(userId: string): Set<string> {
    const permissions = new Set<string>();
    const userRolesList = this.userRoles.get(userId);

    if (!userRolesList) {
      return permissions;
    }

    userRolesList.forEach((r) => {
      // Check if role assignment has expired
      if (r.expiresAt && r.expiresAt < Date.now()) {
        return;
      }

      const role = this.roles.get(r.roleId);
      role?.permissions.forEach((permission) => permissions.add(permission));
    });

    return permissions;
  }

  /**
   * Get all roles for a user
   */
  getUserRoles(userId: string): RBACRole[] {
    const userRolesList = this.userRoles.get(userId);
    if (!userRolesList) {
      return [];
    }

    return userRolesList
      .filter((r) => !r.expiresAt || r.expiresAt >= Date.now())
      .map((r) => this.roles.get(r.roleId))
      .filter((role) => role !== undefined) as RBACRole[];
  }

  /**
   * Add permission to a role
   */
  addPermissionToRole(roleId: string, permission: string): boolean {
    const role = this.roles.get(roleId);
    if (!role) {
      return false;
    }

    if (!role.permissions.includes(permission)) {
      role.permissions.push(permission);
      this.events.emit('rbac:role:permission:added', { roleId, permission });
    }

    return true;
  }

  /**
   * Remove permission from a role
   */
  removePermissionFromRole(roleId: string, permission: string): boolean {
    const role = this.roles.get(roleId);
    if (!role) {
      return false;
    }

    const initialLength = role.permissions.length;
    role.permissions = role.permissions.filter((p) => p !== permission);

    if (role.permissions.length < initialLength) {
      this.events.emit('rbac:role:permission:removed', { roleId, permission });
      return true;
    }

    return false;
  }

  /**
   * Get all users with a specific role
   */
  getUsersWithRole(roleId: string): string[] {
    const users: string[] = [];

    this.userRoles.forEach((roles, userId) => {
      if (
        roles.some(
          (r) =>
            r.roleId === roleId && (!r.expiresAt || r.expiresAt >= Date.now())
        )
      ) {
        users.push(userId);
      }
    });

    return users;
  }

  /**
   * Clear expired role assignments
   */
  clearExpiredAssignments(): void {
    const now = Date.now();

    this.userRoles.forEach((roles, userId) => {
      const filtered = roles.filter((r) => !r.expiresAt || r.expiresAt >= now);
      if (filtered.length < roles.length) {
        if (filtered.length === 0) {
          this.userRoles.delete(userId);
        } else {
          this.userRoles.set(userId, filtered);
        }
      }
    });

    this.events.emit('rbac:expired:cleared');
  }

  /**
   * Subscribe to RBAC events
   */
  on(event: string, listener: (...args: any[]) => void): void {
    this.events.on(event, listener);
  }

  /**
   * Unsubscribe from RBAC events
   */
  off(event: string, listener: (...args: any[]) => void): void {
    this.events.off(event, listener);
  }
}
