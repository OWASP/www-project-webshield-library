import { ACL } from "../../../src/core/a01-broken-access-control/acl/acl";
import {
  ACLRule,
  ACLQuery,
} from "../../../src/core/a01-broken-access-control/acl/types";

describe("ACL", () => {
  let acl: ACL;

  beforeEach(() => {
    acl = new ACL();
  });

  describe("Basic Access Control", () => {
    beforeEach(() => {
      // Set up some basic rules
      const rules: ACLRule[] = [
        {
          allow: true,
          principal: { type: "user", id: "user1" },
          resource: { type: "document", id: "doc1" },
          permissions: ["read"],
        },
        {
          allow: true,
          principal: { type: "role", id: "admin" },
          resource: { type: "*", id: "*" },
          permissions: "*",
          priority: 100,
        },
      ];

      rules.forEach((rule) => acl.addRule(rule));
    });

    it("should allow permitted access", async () => {
      const query: ACLQuery = {
        principal: { type: "user", id: "user1" },
        resource: { type: "document", id: "doc1" },
        permission: "read",
      };

      const result = await acl.isAllowed(query);
      expect(result).toBe(true);
    });

    it("should deny unpermitted access", async () => {
      const query: ACLQuery = {
        principal: { type: "user", id: "user1" },
        resource: { type: "document", id: "doc1" },
        permission: "write",
      };

      const result = await acl.isAllowed(query);
      expect(result).toBe(false);
    });

    it("should respect rule priority", async () => {
      const query: ACLQuery = {
        principal: { type: "role", id: "admin" },
        resource: { type: "document", id: "doc2" },
        permission: "delete",
      };

      const result = await acl.isAllowed(query);
      expect(result).toBe(true);
    });
  });

  describe("Wildcard Support", () => {
    it("should handle wildcard permissions", async () => {
      acl.addRule({
        allow: true,
        principal: { type: "role", id: "manager" },
        resource: { type: "document", id: "*" },
        permissions: "*",
      });

      const query: ACLQuery = {
        principal: { type: "role", id: "manager" },
        resource: { type: "document", id: "any-doc" },
        permission: "write",
      };

      const result = await acl.isAllowed(query);
      expect(result).toBe(true);
    });
  });

  describe("Conditional Rules", () => {
    it("should evaluate conditions", async () => {
      acl.addRule({
        allow: true,
        principal: { type: "user", id: "user1" },
        resource: { type: "document", id: "doc1" },
        permissions: ["read"],
        conditions: {
          timeOfDay: "business-hours",
        },
      });

      const query: ACLQuery = {
        principal: { type: "user", id: "user1" },
        resource: { type: "document", id: "doc1" },
        permission: "read",
        context: {
          timeOfDay: "business-hours",
        },
      };

      const result = await acl.isAllowed(query);
      expect(result).toBe(true);
    });

    it("should deny when conditions are not met", async () => {
      acl.addRule({
        allow: true,
        principal: { type: "user", id: "user1" },
        resource: { type: "document", id: "doc1" },
        permissions: ["read"],
        conditions: {
          timeOfDay: "business-hours",
        },
      });

      const query: ACLQuery = {
        principal: { type: "user", id: "user1" },
        resource: { type: "document", id: "doc1" },
        permission: "read",
        context: {
          timeOfDay: "after-hours",
        },
      };

      const result = await acl.isAllowed(query);
      expect(result).toBe(false);
    });
  });

  describe("Permission Management", () => {
    it("should return all permissions for a principal on a resource", () => {
      acl.addRule({
        allow: true,
        principal: { type: "user", id: "user1" },
        resource: { type: "document", id: "doc1" },
        permissions: ["read", "write"],
      });

      const permissions = acl.getPermissions(
        { type: "user", id: "user1" },
        { type: "document", id: "doc1" }
      );

      expect(permissions).toContain("read");
      expect(permissions).toContain("write");
      expect(permissions).not.toContain("delete");
    });
  });
});
