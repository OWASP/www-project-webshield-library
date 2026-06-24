import { RBAC } from "../../../src/core/a01-broken-access-control/rbac/rbac";
import {
  Role,
  Subject,
  Resource,
  AccessRequest,
} from "../../../src/core/a01-broken-access-control/rbac/types";

describe("RBAC", () => {
  let rbac: RBAC;

  beforeEach(() => {
    rbac = new RBAC();
  });

  describe("Role Management", () => {
    it("should add a role successfully", () => {
      const role: Role = {
        name: "admin",
        permissions: [{ action: "read", resource: "document" }],
      };

      expect(() => rbac.addRole(role)).not.toThrow();
    });

    it("should throw error when adding duplicate role", () => {
      const role: Role = {
        name: "admin",
        permissions: [{ action: "read", resource: "document" }],
      };

      rbac.addRole(role);
      expect(() => rbac.addRole(role)).toThrow("Role 'admin' already exists");
    });

    it("should handle role inheritance", () => {
      const parentRole: Role = {
        name: "user",
        permissions: [{ action: "read", resource: "document" }],
      };

      const childRole: Role = {
        name: "admin",
        permissions: [{ action: "write", resource: "document" }],
        inheritFrom: ["user"],
      };

      rbac.addRole(parentRole);
      rbac.addRole(childRole);

      const subject: Subject = {
        id: "1",
        roles: ["admin"],
      };

      const readRequest: AccessRequest = {
        subject,
        action: "read",
        resource: { type: "document", id: "1" },
      };

      const writeRequest: AccessRequest = {
        subject,
        action: "write",
        resource: { type: "document", id: "1" },
      };

      return Promise.all([
        expect(rbac.can(readRequest)).resolves.toBe(true),
        expect(rbac.can(writeRequest)).resolves.toBe(true),
      ]);
    });
  });

  describe("Permission Checking", () => {
    beforeEach(() => {
      const userRole: Role = {
        name: "user",
        permissions: [{ action: "read", resource: "document" }],
      };

      const adminRole: Role = {
        name: "admin",
        permissions: [
          { action: "write", resource: "document" },
          { action: "delete", resource: "document" },
        ],
        inheritFrom: ["user"],
      };

      rbac.addRole(userRole);
      rbac.addRole(adminRole);
    });

    it("should allow permitted actions", async () => {
      const subject: Subject = {
        id: "1",
        roles: ["user"],
      };

      const request: AccessRequest = {
        subject,
        action: "read",
        resource: { type: "document", id: "1" },
      };

      const result = await rbac.can(request);
      expect(result).toBe(true);
    });

    it("should deny unpermitted actions", async () => {
      const subject: Subject = {
        id: "1",
        roles: ["user"],
      };

      const request: AccessRequest = {
        subject,
        action: "write",
        resource: { type: "document", id: "1" },
      };

      const result = await rbac.can(request);
      expect(result).toBe(false);
    });

    it("should support custom permission verifiers", async () => {
      rbac.registerPermissionVerifier("read", async (request) => {
        // Only allow reading documents with even IDs
        return parseInt(request.resource.id) % 2 === 0;
      });

      const subject: Subject = {
        id: "1",
        roles: ["user"],
      };

      const allowedRequest: AccessRequest = {
        subject,
        action: "read",
        resource: { type: "document", id: "2" },
      };

      const deniedRequest: AccessRequest = {
        subject,
        action: "read",
        resource: { type: "document", id: "1" },
      };

      const [allowedResult, deniedResult] = await Promise.all([
        rbac.can(allowedRequest),
        rbac.can(deniedRequest),
      ]);

      expect(allowedResult).toBe(true);
      expect(deniedResult).toBe(false);
    });
  });
});
