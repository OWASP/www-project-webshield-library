import { URLAccessControl } from "../../../src/core/a01-broken-access-control/url-control/url-access-control";
import {
  URLRule,
  URLContext,
} from "../../../src/core/a01-broken-access-control/url-control/types";

describe("URLAccessControl", () => {
  let urlAccessControl: URLAccessControl;

  beforeEach(() => {
    urlAccessControl = new URLAccessControl({
      defaultPolicy: "deny",
    });
  });

  describe("Basic URL Access Control", () => {
    beforeEach(() => {
      const rules: URLRule[] = [
        {
          pattern: { pattern: "/api/public/*" },
          allow: true,
        },
        {
          pattern: { pattern: "/api/admin/*", method: "GET" },
          allow: true,
          roles: ["admin"],
        },
        {
          pattern: { pattern: "/api/users/{id}" },
          allow: true,
          customCheck: (context) => {
            const userId = context.user?.id;
            const urlId = context.url.split("/").pop();
            return userId === urlId;
          },
        },
      ];

      rules.forEach((rule) => urlAccessControl.addRule(rule));
    });

    it("should allow access to public URLs", async () => {
      const context: URLContext = {
        url: "/api/public/data",
        method: "GET",
      };

      const result = await urlAccessControl.isAllowed(context);
      expect(result).toBe(true);
    });

    it("should deny access to admin URLs for non-admin users", async () => {
      const context: URLContext = {
        url: "/api/admin/users",
        method: "GET",
        user: {
          roles: ["user"],
        },
      };

      const result = await urlAccessControl.isAllowed(context);
      expect(result).toBe(false);
    });

    it("should allow access to admin URLs for admin users", async () => {
      const context: URLContext = {
        url: "/api/admin/users",
        method: "GET",
        user: {
          roles: ["admin"],
        },
      };

      const result = await urlAccessControl.isAllowed(context);
      expect(result).toBe(true);
    });

    it("should allow users to access their own resources", async () => {
      const context: URLContext = {
        url: "/api/users/123",
        method: "GET",
        user: {
          id: "123",
          roles: ["user"],
        },
      };

      const result = await urlAccessControl.isAllowed(context);
      expect(result).toBe(true);
    });

    it("should deny users access to other users resources", async () => {
      const context: URLContext = {
        url: "/api/users/456",
        method: "GET",
        user: {
          id: "123",
          roles: ["user"],
        },
      };

      const result = await urlAccessControl.isAllowed(context);
      expect(result).toBe(false);
    });
  });

  describe("Pattern Matching", () => {
    it("should support wildcard patterns", async () => {
      urlAccessControl.addRule({
        pattern: { pattern: "/api/*/public/**" },
        allow: true,
      });

      const context: URLContext = {
        url: "/api/v1/public/data/items",
        method: "GET",
      };

      const result = await urlAccessControl.isAllowed(context);
      expect(result).toBe(true);
    });

    it("should support HTTP method restrictions", async () => {
      urlAccessControl.addRule({
        pattern: { pattern: "/api/data", method: ["GET", "POST"] },
        allow: true,
      });

      const results = await Promise.all([
        urlAccessControl.isAllowed({ url: "/api/data", method: "GET" }),
        urlAccessControl.isAllowed({ url: "/api/data", method: "POST" }),
        urlAccessControl.isAllowed({ url: "/api/data", method: "DELETE" }),
      ]);

      expect(results).toEqual([true, true, false]);
    });

    it("should support case sensitivity options", async () => {
      urlAccessControl.addRule({
        pattern: { pattern: "/API/data", caseSensitive: true },
        allow: true,
      });

      const results = await Promise.all([
        urlAccessControl.isAllowed({ url: "/API/data", method: "GET" }),
        urlAccessControl.isAllowed({ url: "/api/data", method: "GET" }),
      ]);

      expect(results).toEqual([true, false]);
    });
  });

  describe("Rule Priority", () => {
    it("should respect rule priority", async () => {
      urlAccessControl.addRule({
        pattern: { pattern: "/api/*" },
        allow: false,
        priority: 1,
      });

      urlAccessControl.addRule({
        pattern: { pattern: "/api/public/*" },
        allow: true,
        priority: 2,
      });

      const context: URLContext = {
        url: "/api/public/data",
        method: "GET",
      };

      const result = await urlAccessControl.isAllowed(context);
      expect(result).toBe(true);
    });
  });
});
