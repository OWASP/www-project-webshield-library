import {
  RBAC,
  Role,
  Permission,
  Subject,
  Resource,
  AccessRequest,
  DuplicateRoleError,
  RoleNotFoundError,
  InheritedRoleError,
  InvalidParentRoleError,
} from "./exports";

describe("RBAC", () => {
  let rbac: RBAC;

  const adminPermissions: Permission[] = [
    { action: "read", resource: "*" },
    { action: "write", resource: "*" },
  ];

  const userPermissions: Permission[] = [
    { action: "read", resource: "posts" },
    { action: "write", resource: "posts", conditions: { owner: "${userId}" } },
  ];

  const guestPermissions: Permission[] = [
    { action: "read", resource: "posts" },
  ];

  beforeEach(() => {
    rbac = new RBAC({
      caseSensitive: false,
      hierarchical: true,
      dynamicPermissions: true,
    });
  });

  describe("Role Management", () => {
    it("should add a new role successfully", () => {
      const role: Role = {
        name: "admin",
        permissions: adminPermissions,
      };

      rbac.addRole(role);
      expect(rbac.getSubjectPermissions({ id: "1", roles: ["admin"] })).toEqual(
        adminPermissions
      );
    });

    it("should throw error when adding duplicate role", () => {
      const role: Role = {
        name: "admin",
        permissions: adminPermissions,
      };

      rbac.addRole(role);
      expect(() => rbac.addRole(role)).toThrow(DuplicateRoleError);
    });

    it("should handle case sensitivity according to options", () => {
      const role: Role = {
        name: "Admin",
        permissions: adminPermissions,
      };

      rbac.addRole(role);
      expect(() => rbac.addRole({ ...role, name: "admin" })).toThrow(
        DuplicateRoleError
      );
    });

    it("should remove role successfully", () => {
      const role: Role = {
        name: "admin",
        permissions: adminPermissions,
      };

      rbac.addRole(role);
      rbac.removeRole("admin");
      expect(() =>
        rbac.getSubjectPermissions({ id: "1", roles: ["admin"] })
      ).toThrow(RoleNotFoundError);
    });

    it("should not remove role that is inherited", () => {
      const adminRole: Role = {
        name: "admin",
        permissions: adminPermissions,
      };

      const superAdminRole: Role = {
        name: "superadmin",
        permissions: [],
        inheritFrom: ["admin"],
      };

      rbac.addRole(adminRole);
      rbac.addRole(superAdminRole);

      expect(() => rbac.removeRole("admin")).toThrow(InheritedRoleError);
    });
  });

  describe("Role Inheritance", () => {
    it("should inherit permissions from parent role", async () => {
      const adminRole: Role = {
        name: "admin",
        permissions: adminPermissions,
      };

      const editorRole: Role = {
        name: "editor",
        permissions: [{ action: "write", resource: "posts" }],
        inheritFrom: ["admin"],
      };

      rbac.addRole(adminRole);
      rbac.addRole(editorRole);

      const subject: Subject = { id: "1", roles: ["editor"] };
      const request: AccessRequest = {
        subject,
        action: "read",
        resource: { type: "users", id: "2" },
      };

      expect(await rbac.can(request)).toBe(true);
    });

    it("should throw error when parent role does not exist", () => {
      const role: Role = {
        name: "editor",
        permissions: [],
        inheritFrom: ["admin"],
      };

      expect(() => rbac.addRole(role)).toThrow(InvalidParentRoleError);
    });
  });

  describe("Permission Checking", () => {
    it("should check direct permissions correctly", async () => {
      const userRole: Role = {
        name: "user",
        permissions: userPermissions,
      };

      rbac.addRole(userRole);

      const subject: Subject = { id: "1", roles: ["user"] };
      const request: AccessRequest = {
        subject,
        action: "read",
        resource: { type: "posts", id: "1" },
      };

      expect(await rbac.can(request)).toBe(true);
    });

    it("should evaluate conditions correctly", async () => {
      const userRole: Role = {
        name: "user",
        permissions: userPermissions,
      };

      rbac.addRole(userRole);

      const subject: Subject = {
        id: "1",
        roles: ["user"],
        attributes: { userId: "1" },
      };

      const request: AccessRequest = {
        subject,
        action: "write",
        resource: { type: "posts", id: "1" },
        context: { owner: "1" },
      };

      expect(await rbac.can(request)).toBe(true);

      const unauthorizedRequest: AccessRequest = {
        subject,
        action: "write",
        resource: { type: "posts", id: "1" },
        context: { owner: "2" },
      };

      expect(await rbac.can(unauthorizedRequest)).toBe(false);
    });
  });

  describe("Custom Permission Verifiers", () => {
    it("should use custom permission verifier", async () => {
      const userRole: Role = {
        name: "user",
        permissions: [{ action: "custom", resource: "posts" }],
      };

      rbac.addRole(userRole);
      rbac.registerPermissionVerifier(
        "custom",
        async (request: AccessRequest) => {
          return request.subject.id === "1";
        }
      );

      const allowedRequest: AccessRequest = {
        subject: { id: "1", roles: ["user"] },
        action: "custom",
        resource: { type: "posts", id: "1" },
      };

      const deniedRequest: AccessRequest = {
        subject: { id: "2", roles: ["user"] },
        action: "custom",
        resource: { type: "posts", id: "1" },
      };

      expect(await rbac.can(allowedRequest)).toBe(true);
      expect(await rbac.can(deniedRequest)).toBe(false);
    });
  });

  describe("Wildcard Permissions", () => {
    it("should handle wildcard resource permissions", async () => {
      const adminRole: Role = {
        name: "admin",
        permissions: [{ action: "read", resource: "*" }],
      };

      rbac.addRole(adminRole);

      const request: AccessRequest = {
        subject: { id: "1", roles: ["admin"] },
        action: "read",
        resource: { type: "any-resource", id: "1" },
      };

      expect(await rbac.can(request)).toBe(true);
    });
  });
});
