/**
 * ACLManager Tests
 */

import { ACLManager } from '../ACLManager';

describe('ACLManager', () => {
  let acl: ACLManager;

  beforeEach(() => {
    acl = new ACLManager();
  });

  describe('Resource Management', () => {
    it('should create a resource', () => {
      const resource = acl.createResource('resource1', 'Test Resource', 'owner1');

      expect(resource.id).toBe('resource1');
      expect(resource.name).toBe('Test Resource');
      expect(resource.ownerId).toBe('owner1');
      expect(resource.isPublic).toBe(false);
    });

    it('should create a public resource', () => {
      const resource = acl.createResource('resource1', 'Public Resource', 'owner1', true);

      expect(resource.isPublic).toBe(true);
    });

    it('should get a resource', () => {
      acl.createResource('resource1', 'Test Resource', 'owner1');
      const resource = acl.getResource('resource1');

      expect(resource?.name).toBe('Test Resource');
    });

    it('should return undefined for non-existent resource', () => {
      expect(acl.getResource('non-existent')).toBeUndefined();
    });

    it('should delete a resource', () => {
      acl.createResource('resource1', 'Test Resource', 'owner1');
      expect(acl.deleteResource('resource1')).toBe(true);
      expect(acl.getResource('resource1')).toBeUndefined();
    });
  });

  describe('Permission Management', () => {
    beforeEach(() => {
      acl.createResource('resource1', 'Test Resource', 'owner1');
    });

    it('should grant permission', () => {
      acl.grantPermission('resource1', 'user1', 'read', 'owner1');

      expect(acl.hasPermission('resource1', 'user1', 'read')).toBe(true);
    });

    it('should throw error for non-existent resource', () => {
      expect(() => {
        acl.grantPermission('non-existent', 'user1', 'read', 'owner1');
      }).toThrow('Resource "non-existent" does not exist');
    });

    it('should revoke permission', () => {
      acl.grantPermission('resource1', 'user1', 'read', 'owner1');
      expect(acl.revokePermission('resource1', 'user1', 'read')).toBe(true);
      expect(acl.hasPermission('resource1', 'user1', 'read')).toBe(false);
    });

    it('should handle expired permissions', () => {
      const expiredTime = Date.now() - 1000; // 1 second ago
      acl.grantPermission('resource1', 'user1', 'read', 'owner1', expiredTime);

      expect(acl.hasPermission('resource1', 'user1', 'read')).toBe(false);
    });

    it('should get resource permissions', () => {
      acl.grantPermission('resource1', 'user1', 'read', 'owner1');
      acl.grantPermission('resource1', 'user2', 'write', 'owner1');

      const permissions = acl.getResourcePermissions('resource1');
      expect(permissions).toHaveLength(2);
    });
  });

  describe('Permission Checking', () => {
    beforeEach(() => {
      acl.createResource('resource1', 'Test Resource', 'owner1');
    });

    it('owner should have all permissions', () => {
      expect(acl.hasPermission('resource1', 'owner1', 'read')).toBe(true);
      expect(acl.hasPermission('resource1', 'owner1', 'write')).toBe(true);
      expect(acl.hasPermission('resource1', 'owner1', 'delete')).toBe(true);
    });

    it('should check ownership', () => {
      expect(acl.isOwner('resource1', 'owner1')).toBe(true);
      expect(acl.isOwner('resource1', 'user1')).toBe(false);
    });

    it('public resource should be readable by anyone', () => {
      acl.deleteResource('resource1');
      acl.createResource('resource1', 'Public Resource', 'owner1', true);

      expect(acl.hasPermission('resource1', 'any-user', 'read')).toBe(true);
      expect(acl.hasPermission('resource1', 'any-user', 'write')).toBe(false);
    });
  });

  describe('Resource Access', () => {
    it('should get user accessible resources', () => {
      acl.createResource('resource1', 'Resource 1', 'user1');
      acl.createResource('resource2', 'Resource 2', 'owner1');
      acl.createResource('resource3', 'Public Resource', 'owner1', true);

      acl.grantPermission('resource2', 'user1', 'read', 'owner1');

      const resources = acl.getUserAccessibleResources('user1');

      expect(resources).toHaveLength(3); // Own resource, granted access, and public
    });

    it('should filter resources by action', () => {
      acl.createResource('resource1', 'Resource 1', 'user1');
      acl.grantPermission('resource1', 'user2', 'read', 'user1');
      acl.grantPermission('resource1', 'user3', 'write', 'user1');

      const readAccessResources = acl.getUserAccessibleResources('user2', 'read');
      const writeAccessResources = acl.getUserAccessibleResources('user2', 'write');

      expect(readAccessResources).toHaveLength(1);
      expect(writeAccessResources).toHaveLength(0);
    });
  });

  describe('Ownership Transfer', () => {
    beforeEach(() => {
      acl.createResource('resource1', 'Test Resource', 'owner1');
    });

    it('should transfer ownership', () => {
      acl.transferOwnership('resource1', 'owner2');

      expect(acl.isOwner('resource1', 'owner2')).toBe(true);
      expect(acl.isOwner('resource1', 'owner1')).toBe(false);
    });

    it('should handle invalid resource in ownership transfer', () => {
      expect(acl.transferOwnership('non-existent', 'owner2')).toBe(false);
    });
  });

  describe('Permission Expiry', () => {
    it('should detect expired permission', () => {
      const permission = {
        resourceId: 'resource1',
        userId: 'user1',
        action: 'read' as const,
        grantedBy: 'admin',
        grantedAt: Date.now(),
        expiresAt: Date.now() - 1000,
      };

      expect(acl.isPermissionExpired(permission)).toBe(true);
    });

    it('should not consider non-expiring permission as expired', () => {
      const permission = {
        resourceId: 'resource1',
        userId: 'user1',
        action: 'read' as const,
        grantedBy: 'admin',
        grantedAt: Date.now(),
      };

      expect(acl.isPermissionExpired(permission)).toBe(false);
    });

    it('should clear expired permissions', () => {
      acl.createResource('resource1', 'Test', 'owner1');
      acl.grantPermission('resource1', 'user1', 'read', 'owner1', Date.now() - 1000);
      acl.grantPermission('resource1', 'user2', 'write', 'owner1'); // No expiry

      acl.clearExpiredPermissions();

      const permissions = acl.getResourcePermissions('resource1');
      expect(permissions).toHaveLength(1);
      expect(permissions[0].userId).toBe('user2');
    });
  });

  describe('Events', () => {
    it('should emit resource:created event', () => {
      const spy = jest.fn();
      acl.on('acl:resource:created', spy);

      acl.createResource('resource1', 'Test', 'owner1');

      expect(spy).toHaveBeenCalled();
    });

    it('should emit permission:granted event', () => {
      acl.createResource('resource1', 'Test', 'owner1');

      const spy = jest.fn();
      acl.on('acl:permission:granted', spy);

      acl.grantPermission('resource1', 'user1', 'read', 'owner1');

      expect(spy).toHaveBeenCalled();
    });
  });
});
