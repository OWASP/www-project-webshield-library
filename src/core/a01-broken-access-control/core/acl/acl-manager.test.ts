import { ACLManager } from "./acl-manager";
import { ACLPermission, ACLRole, ACLConfig } from "./interfaces";
import {
  RoleNotFoundError,
  DuplicateRoleError,
  CircularDependencyError,
  MaxInheritanceDepthError,
} from "./errors";

describe("ACLManager", () => {
  let aclManager: ACLManager;
  const basicConfig: ACLConfig = {
    defaultRole: "guest",
    defaultAllow: false,
    enableInheritance: true,
    maxInheritanceDepth: 5,
    enableCaching: true,
    cacheTTL: 300000,
  };

  const adminPermissions: ACLPermission[] = [
    {
      action: "read",
      resource: "users",
      attributes: ["id", "name", "email", "role"],
    },
    {
      action: "write",
      resource: "users",
    },
  ];

  const userPermissions: ACLPermission[] = [
    {
      action: "read",
      resource: "users",
      attributes: ["id", "name"],
      conditions: { userId: "${currentUserId}" },
    },
  ];

  beforeEach(() => {
    aclManager = new ACLManager(basicConfig);
  });

  describe("Role Management", () => {
    it("should add a new role successfully", () => {
      const role: ACLRole = { roleId: "admin", permissions: adminPermissions };
      aclManager.addRole(role);
      expect(aclManager.getRolePermissions("admin")).toEqual(adminPermissions);
    });

    it("should throw error when adding duplicate role", () => {
      const role: ACLRole = { roleId: "admin", permissions: adminPermissions };
      aclManager.addRole(role);
      expect(() => aclManager.addRole(role)).toThrow(DuplicateRoleError);
    });

    it("should remove a role successfully", () => {
      const role: ACLRole = { roleId: "admin", permissions: adminPermissions };
      aclManager.addRole(role);
      aclManager.removeRole("admin");
      expect(() => aclManager.getRolePermissions("admin")).toThrow(
        RoleNotFoundError
      );
    });
  });

  describe("Permission Management", () => {
    it("should add permissions to existing role", () => {
      const role: ACLRole = { roleId: "user", permissions: [] };
      aclManager.addRole(role);
      aclManager.addPermissions("user", userPermissions);
      expect(aclManager.getRolePermissions("user")).toEqual(userPermissions);
    });

    it("should remove permissions from role", () => {
      const role: ACLRole = { roleId: "admin", permissions: adminPermissions };
      aclManager.addRole(role);
      aclManager.removePermissions("admin", [adminPermissions[0]]);
      expect(aclManager.getRolePermissions("admin")).toEqual([
        adminPermissions[1],
      ]);
    });
  });

  describe("Permission Checking", () => {
    it("should check permission successfully", () => {
      const role: ACLRole = { roleId: "admin", permissions: adminPermissions };
      aclManager.addRole(role);
      expect(aclManager.checkPermission("admin", "read", "users")).toBe(true);
      expect(aclManager.checkPermission("admin", "delete", "users")).toBe(
        false
      );
    });

    it("should evaluate conditions correctly", () => {
      const role: ACLRole = { roleId: "user", permissions: userPermissions };
      aclManager.addRole(role);
      expect(
        aclManager.checkPermission("user", "read", "users", {
          attributes: { currentUserId: "123" },
          userId: "123",
        })
      ).toBe(true);
      expect(
        aclManager.checkPermission("user", "read", "users", {
          attributes: { currentUserId: "123" },
          userId: "456",
        })
      ).toBe(false);
    });
  });

  describe("Role Inheritance", () => {
    it("should handle role inheritance correctly", () => {
      const editorPermissions: ACLPermission[] = [
        {
          action: "write",
          resource: "posts",
        },
      ];

      const adminRole: ACLRole = {
        roleId: "admin",
        permissions: adminPermissions,
      };

      const editorRole: ACLRole = {
        roleId: "editor",
        permissions: editorPermissions,
        extends: ["admin"],
      };

      aclManager.addRole(adminRole);
      aclManager.addRole(editorRole);

      expect(aclManager.checkPermission("editor", "write", "posts")).toBe(true);
      expect(aclManager.checkPermission("editor", "read", "users")).toBe(true);
    });

    it("should detect circular dependencies", () => {
      const role1: ACLRole = {
        roleId: "role1",
        permissions: [],
        extends: ["role2"],
      };

      const role2: ACLRole = {
        roleId: "role2",
        permissions: [],
        extends: ["role1"],
      };

      aclManager.addRole(role1);
      aclManager.addRole(role2);

      expect(() => aclManager.getRolePermissions("role1")).toThrow(
        CircularDependencyError
      );
    });

    it("should respect max inheritance depth", () => {
      const createRole = (id: number): ACLRole => ({
        roleId: `role${id}`,
        permissions: [],
        extends: id > 1 ? [`role${id - 1}`] : undefined,
      });

      // Create a chain of roles that exceeds maxInheritanceDepth
      for (let i = 1; i <= 7; i++) {
        aclManager.addRole(createRole(i));
      }

      expect(() => aclManager.getRolePermissions("role7")).toThrow(
        MaxInheritanceDepthError
      );
    });
  });

  describe("Attribute Access", () => {
    it("should check attribute access correctly", () => {
      const role: ACLRole = { roleId: "admin", permissions: adminPermissions };
      aclManager.addRole(role);
      expect(
        aclManager.checkAttributeAccess("admin", "users", ["id", "name"])
      ).toBe(true);
      expect(
        aclManager.checkAttributeAccess("admin", "users", ["password"])
      ).toBe(false);
    });
  });

  describe("Caching", () => {
    it("should cache permission checks", () => {
      const role: ACLRole = { roleId: "admin", permissions: adminPermissions };
      aclManager.addRole(role);

      // First check (should cache)
      const result1 = aclManager.checkPermission("admin", "read", "users");

      // Remove the permission (but it should still be cached)
      aclManager.removePermissions("admin", adminPermissions);

      // Second check (should use cache)
      const result2 = aclManager.checkPermission("admin", "read", "users");

      expect(result1).toBe(true);
      expect(result2).toBe(true); // Should still be true due to caching
    });

    it("should clear cache when modifying roles or permissions", () => {
      const role: ACLRole = { roleId: "admin", permissions: adminPermissions };
      aclManager.addRole(role);

      // First check (should cache)
      const result1 = aclManager.checkPermission("admin", "read", "users");

      // Modify permissions (should clear cache)
      aclManager.removePermissions("admin", adminPermissions);

      // Second check (should not use cache)
      const result2 = aclManager.checkPermission("admin", "read", "users");

      expect(result1).toBe(true);
      expect(result2).toBe(false); // Should be false because cache was cleared
    });
  });
});
