/**
 * RBACManager Tests
 */

import { RBACManager } from '../RBACManager';
import { RBACRole } from '../types';

describe('RBACManager', () => {
  let rbac: RBACManager;

  beforeEach(() => {
    rbac = new RBACManager();
  });

  describe('Role Management', () => {
    it('should add a role', () => {
      const role: RBACRole = {
        id: 'admin',
        name: 'Administrator',
        permissions: ['read', 'write', 'delete'],
      };

      rbac.addRole(role);
      expect(rbac.getRole('admin')).toEqual(role);
    });

    it('should retrieve a role', () => {
      const role: RBACRole = {
        id: 'user',
        name: 'User',
        permissions: ['read'],
      };

      rbac.addRole(role);
      expect(rbac.getRole('user')).toEqual(role);
    });

    it('should return undefined for non-existent role', () => {
      expect(rbac.getRole('non-existent')).toBeUndefined();
    });

    it('should remove a role', () => {
      const role: RBACRole = {
        id: 'guest',
        name: 'Guest',
        permissions: [],
      };

      rbac.addRole(role);
      expect(rbac.removeRole('guest')).toBe(true);
      expect(rbac.getRole('guest')).toBeUndefined();
    });

    it('should get all roles', () => {
      const role1: RBACRole = {
        id: 'admin',
        name: 'Admin',
        permissions: ['read', 'write'],
      };
      const role2: RBACRole = {
        id: 'user',
        name: 'User',
        permissions: ['read'],
      };

      rbac.addRole(role1);
      rbac.addRole(role2);

      const allRoles = rbac.getAllRoles();
      expect(allRoles).toHaveLength(2);
      expect(allRoles).toContainEqual(role1);
      expect(allRoles).toContainEqual(role2);
    });
  });

  describe('User Role Assignment', () => {
    beforeEach(() => {
      const adminRole: RBACRole = {
        id: 'admin',
        name: 'Admin',
        permissions: ['read', 'write', 'delete'],
      };
      rbac.addRole(adminRole);
    });

    it('should assign role to user', () => {
      rbac.assignRoleToUser('user1', 'admin', 'system');
      expect(rbac.hasRole('user1', 'admin')).toBe(true);
    });

    it('should throw error for non-existent role', () => {
      expect(() => rbac.assignRoleToUser('user1', 'non-existent', 'system')).toThrow(
        'Role "non-existent" does not exist'
      );
    });

    it('should remove role from user', () => {
      rbac.assignRoleToUser('user1', 'admin', 'system');
      expect(rbac.removeRoleFromUser('user1', 'admin')).toBe(true);
      expect(rbac.hasRole('user1', 'admin')).toBe(false);
    });

    it('should get user roles', () => {
      rbac.assignRoleToUser('user1', 'admin', 'system');
      const roles = rbac.getUserRoles('user1');

      expect(roles).toHaveLength(1);
      expect(roles[0].id).toBe('admin');
    });

    it('should handle expired role assignments', () => {
      const expiredTime = Date.now() - 1000; // 1 second ago
      rbac.assignRoleToUser('user1', 'admin', 'system', expiredTime);

      expect(rbac.hasRole('user1', 'admin')).toBe(false);
    });
  });

  describe('Permission Checking', () => {
    beforeEach(() => {
      const adminRole: RBACRole = {
        id: 'admin',
        name: 'Admin',
        permissions: ['read', 'write', 'delete'],
      };
      const userRole: RBACRole = {
        id: 'user',
        name: 'User',
        permissions: ['read'],
      };

      rbac.addRole(adminRole);
      rbac.addRole(userRole);
      rbac.assignRoleToUser('user1', 'admin', 'system');
      rbac.assignRoleToUser('user2', 'user', 'system');
    });

    it('should check if user has permission', () => {
      expect(rbac.hasPermission('user1', 'write')).toBe(true);
      expect(rbac.hasPermission('user2', 'write')).toBe(false);
    });

    it('should check if user has all permissions', () => {
      expect(rbac.hasAllPermissions('user1', ['read', 'write'])).toBe(true);
      expect(rbac.hasAllPermissions('user2', ['read', 'write'])).toBe(false);
    });

    it('should check if user has any permission', () => {
      expect(rbac.hasAnyPermission('user1', ['write', 'admin'])).toBe(true);
      expect(rbac.hasAnyPermission('user2', ['write', 'delete'])).toBe(false);
    });

    it('should get user permissions', () => {
      const permissions = rbac.getUserPermissions('user1');
      expect(permissions.has('read')).toBe(true);
      expect(permissions.has('write')).toBe(true);
      expect(permissions.has('delete')).toBe(true);
    });
  });

  describe('Role Permissions', () => {
    beforeEach(() => {
      const role: RBACRole = {
        id: 'editor',
        name: 'Editor',
        permissions: ['read'],
      };
      rbac.addRole(role);
    });

    it('should add permission to role', () => {
      expect(rbac.addPermissionToRole('editor', 'write')).toBe(true);
      expect(rbac.getRole('editor')?.permissions).toContain('write');
    });

    it('should remove permission from role', () => {
      rbac.addPermissionToRole('editor', 'write');
      expect(rbac.removePermissionFromRole('editor', 'write')).toBe(true);
      expect(rbac.getRole('editor')?.permissions).not.toContain('write');
    });

    it('should not add duplicate permission', () => {
      rbac.addPermissionToRole('editor', 'read');
      const permissions = rbac.getRole('editor')?.permissions ?? [];
      const readCount = permissions.filter((p) => p === 'read').length;
      expect(readCount).toBe(1);
    });
  });

  describe('Events', () => {
    it('should emit role:added event', () => {
      const spy = jest.fn();
      rbac.on('rbac:role:added', spy);

      const role: RBACRole = {
        id: 'test',
        name: 'Test',
        permissions: [],
      };

      rbac.addRole(role);
      expect(spy).toHaveBeenCalled();
    });

    it('should emit user:role:assigned event', () => {
      const spy = jest.fn();
      rbac.on('rbac:user:role:assigned', spy);

      const role: RBACRole = {
        id: 'admin',
        name: 'Admin',
        permissions: [],
      };
      rbac.addRole(role);
      rbac.assignRoleToUser('user1', 'admin', 'system');

      expect(spy).toHaveBeenCalled();
    });
  });
});
