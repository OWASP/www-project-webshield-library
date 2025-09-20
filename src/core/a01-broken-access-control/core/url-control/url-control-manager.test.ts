import {
  URLControlManager,
  URLPattern,
  URLRequestContext,
  InvalidPatternError,
  PatternConflictError,
  RateLimitExceededError,
  MissingHeaderError,
  TimeRestrictedError,
  IPRestrictedError,
} from "./index";

describe("URLControlManager", () => {
  let manager: URLControlManager;

  beforeEach(() => {
    manager = new URLControlManager({
      caseSensitive: false,
      defaultAllow: false,
      cache: {
        enabled: true,
        maxSize: 100,
        ttl: 1000,
      },
    });
  });

  describe("Pattern Management", () => {
    it("should add valid patterns", () => {
      const pattern: URLPattern = {
        pattern: "/api/users/*",
        methods: ["GET"],
        allow: true,
      };

      expect(() => manager.addPattern(pattern)).not.toThrow();
    });

    it("should throw on invalid patterns", () => {
      const pattern: URLPattern = {
        pattern: "", // Invalid empty pattern
        methods: ["GET"],
        allow: true,
      };

      expect(() => manager.addPattern(pattern)).toThrow(InvalidPatternError);
    });

    it("should throw on conflicting patterns", () => {
      const pattern1: URLPattern = {
        pattern: "/api/users/*",
        methods: ["GET"],
        allow: true,
      };

      const pattern2: URLPattern = {
        pattern: "/api/users/*",
        methods: ["GET"],
        allow: false,
      };

      manager.addPattern(pattern1);
      expect(() => manager.addPattern(pattern2)).toThrow(PatternConflictError);
    });
  });

  describe("Access Control", () => {
    it("should allow access based on matching pattern", async () => {
      const pattern: URLPattern = {
        pattern: "/api/users/*",
        methods: ["GET"],
        allow: true,
      };

      manager.addPattern(pattern);

      const context: URLRequestContext = {
        url: "/api/users/123",
        method: "GET",
      };

      const result = await manager.checkAccess(context);
      expect(result.allowed).toBe(true);
    });

    it("should deny access when no pattern matches", async () => {
      const pattern: URLPattern = {
        pattern: "/api/users/*",
        methods: ["GET"],
        allow: true,
      };

      manager.addPattern(pattern);

      const context: URLRequestContext = {
        url: "/api/posts/123",
        method: "GET",
      };

      const result = await manager.checkAccess(context);
      expect(result.allowed).toBe(false);
    });

    it("should respect method restrictions", async () => {
      const pattern: URLPattern = {
        pattern: "/api/users/*",
        methods: ["GET"],
        allow: true,
      };

      manager.addPattern(pattern);

      const context: URLRequestContext = {
        url: "/api/users/123",
        method: "POST",
      };

      const result = await manager.checkAccess(context);
      expect(result.allowed).toBe(false);
    });

    it("should handle ALL methods correctly", async () => {
      const pattern: URLPattern = {
        pattern: "/api/users/*",
        methods: "ALL",
        allow: true,
      };

      manager.addPattern(pattern);

      const getContext: URLRequestContext = {
        url: "/api/users/123",
        method: "GET",
      };

      const postContext: URLRequestContext = {
        url: "/api/users/123",
        method: "POST",
      };

      const getResult = await manager.checkAccess(getContext);
      const postResult = await manager.checkAccess(postContext);

      expect(getResult.allowed).toBe(true);
      expect(postResult.allowed).toBe(true);
    });
  });

  describe("Role Conditions", () => {
    it("should check role conditions", async () => {
      const pattern: URLPattern = {
        pattern: "/api/admin/*",
        methods: ["GET"],
        allow: true,
        conditions: [
          {
            type: "role",
            config: {
              type: "role",
              roles: ["admin"],
            },
            errorMessage: "Admin access required",
          },
        ],
      };

      manager.addPattern(pattern);

      const adminContext: URLRequestContext = {
        url: "/api/admin/stats",
        method: "GET",
        user: {
          id: "1",
          roles: ["admin"],
        },
      };

      const userContext: URLRequestContext = {
        url: "/api/admin/stats",
        method: "GET",
        user: {
          id: "2",
          roles: ["user"],
        },
      };

      const adminResult = await manager.checkAccess(adminContext);
      const userResult = await manager.checkAccess(userContext);

      expect(adminResult.allowed).toBe(true);
      expect(userResult.allowed).toBe(false);
      expect(userResult.error).toBe("Admin access required");
    });
  });

  describe("Rate Limiting", () => {
    it("should enforce rate limits", async () => {
      const pattern: URLPattern = {
        pattern: "/api/users/*",
        methods: ["GET"],
        allow: true,
        conditions: [
          {
            type: "rate",
            config: {
              type: "rate",
              limit: 2,
              window: 60,
              by: "ip",
            },
          },
        ],
      };

      manager.addPattern(pattern);

      const context: URLRequestContext = {
        url: "/api/users/123",
        method: "GET",
        ip: "127.0.0.1",
      };

      // First two requests should succeed
      await expect(manager.checkAccess(context)).resolves.toMatchObject({
        allowed: true,
      });
      await expect(manager.checkAccess(context)).resolves.toMatchObject({
        allowed: true,
      });

      // Third request should fail
      await expect(manager.checkAccess(context)).rejects.toThrow(
        RateLimitExceededError
      );
    });
  });

  describe("Header Conditions", () => {
    it("should check required headers", async () => {
      const pattern: URLPattern = {
        pattern: "/api/secure/*",
        methods: ["GET"],
        allow: true,
        conditions: [
          {
            type: "header",
            config: {
              type: "header",
              headers: {
                "x-api-key": "secret",
              },
            },
          },
        ],
      };

      manager.addPattern(pattern);

      const validContext: URLRequestContext = {
        url: "/api/secure/data",
        method: "GET",
        headers: {
          "x-api-key": "secret",
        },
      };

      const invalidContext: URLRequestContext = {
        url: "/api/secure/data",
        method: "GET",
        headers: {},
      };

      await expect(manager.checkAccess(validContext)).resolves.toMatchObject({
        allowed: true,
      });
      await expect(manager.checkAccess(invalidContext)).rejects.toThrow(
        MissingHeaderError
      );
    });
  });

  describe("Time-based Access", () => {
    it("should enforce time restrictions", async () => {
      const pattern: URLPattern = {
        pattern: "/api/business/*",
        methods: ["GET"],
        allow: true,
        conditions: [
          {
            type: "time",
            config: {
              type: "time",
              start: "09:00",
              end: "17:00",
              days: [1, 2, 3, 4, 5], // Monday to Friday
            },
          },
        ],
      };

      manager.addPattern(pattern);

      const context: URLRequestContext = {
        url: "/api/business/hours",
        method: "GET",
      };

      // Mock current time to Saturday
      const mockDate = new Date("2025-09-20T12:00:00"); // Saturday
      const originalDate = Date;
      jest.spyOn(globalThis, "Date").mockImplementation(() => mockDate);

      await expect(manager.checkAccess(context)).rejects.toThrow(
        TimeRestrictedError
      );

      jest.restoreAllMocks();
    });
  });

  describe("IP Restrictions", () => {
    it("should enforce IP restrictions", async () => {
      const pattern: URLPattern = {
        pattern: "/api/internal/*",
        methods: ["GET"],
        allow: true,
        conditions: [
          {
            type: "ip",
            config: {
              type: "ip",
              allow: ["127.0.0.1", "192.168.1.0/24"],
            },
          },
        ],
      };

      manager.addPattern(pattern);

      const allowedContext: URLRequestContext = {
        url: "/api/internal/data",
        method: "GET",
        ip: "127.0.0.1",
      };

      const blockedContext: URLRequestContext = {
        url: "/api/internal/data",
        method: "GET",
        ip: "1.2.3.4",
      };

      await expect(manager.checkAccess(allowedContext)).resolves.toMatchObject({
        allowed: true,
      });
      await expect(manager.checkAccess(blockedContext)).rejects.toThrow(
        IPRestrictedError
      );
    });
  });

  describe("Custom Conditions", () => {
    it("should support custom validators", async () => {
      const customValidator = jest.fn().mockResolvedValue(true);

      const manager = new URLControlManager({
        validators: {
          "custom-auth": customValidator,
        },
      });

      const pattern: URLPattern = {
        pattern: "/api/custom/*",
        methods: ["GET"],
        allow: true,
        conditions: [
          {
            type: "custom",
            config: {
              type: "custom",
              validator: "custom-auth",
              options: {
                someOption: "value",
              },
            },
          },
        ],
      };

      manager.addPattern(pattern);

      const context: URLRequestContext = {
        url: "/api/custom/endpoint",
        method: "GET",
      };

      await manager.checkAccess(context);

      expect(customValidator).toHaveBeenCalledWith(context, expect.any(Object));
    });
  });

  describe("Caching", () => {
    it("should cache access results", async () => {
      const pattern: URLPattern = {
        pattern: "/api/cached/*",
        methods: ["GET"],
        allow: true,
      };

      manager.addPattern(pattern);

      const context: URLRequestContext = {
        url: "/api/cached/data",
        method: "GET",
      };

      // First request should evaluate pattern
      const result1 = await manager.checkAccess(context);
      expect(result1.allowed).toBe(true);

      // Remove pattern, but result should still be cached
      manager.removePattern("/api/cached/*");

      // Second request should use cache
      const result2 = await manager.checkAccess(context);
      expect(result2.allowed).toBe(true);

      // Clear cache
      manager.clearCache();

      // Third request should evaluate new patterns (none exist)
      const result3 = await manager.checkAccess(context);
      expect(result3.allowed).toBe(false);
    });
  });
});
