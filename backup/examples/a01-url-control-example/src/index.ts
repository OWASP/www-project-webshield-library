import { URLAccessControl } from "owasp-web-shield";

// Initialize URL Access Control
const urlAccessControl = new URLAccessControl({
  defaultPolicy: "deny",
  caseSensitive: false,
  validateQueryParams: true,
});

// Define security rules
const rules = [
  // Public routes
  {
    pattern: { pattern: "/api/public/**" },
    allow: true,
  },

  // Authentication routes
  {
    pattern: { pattern: "/api/auth/*", method: ["POST"] },
    allow: true,
  },

  // User profile - only accessible by the owner
  {
    pattern: { pattern: "/api/users/{userId}/profile" },
    allow: true,
    customCheck: (context) => {
      const requestedUserId = context.url.match(/\/users\/([^/]+)/)?.[1];
      return context.user?.id === requestedUserId;
    },
  },

  // Admin routes
  {
    pattern: { pattern: "/api/admin/*" },
    allow: true,
    roles: ["admin"],
    priority: 100,
  },

  // API version 1 endpoints - require authentication
  {
    pattern: { pattern: "/api/v1/**" },
    allow: true,
    customCheck: (context) => Boolean(context.user?.id),
  },

  // Internal endpoints - strictly controlled
  {
    pattern: {
      pattern: "/api/internal/*",
      method: ["GET", "POST"],
      matchQuery: true,
    },
    allow: true,
    roles: ["internal-service"],
    permissions: ["api:internal:access"],
    priority: 200,
  },
];

// Add rules to the system
rules.forEach((rule) => urlAccessControl.addRule(rule));

// Example usage in an Express-like middleware
async function securityMiddleware(req: any, res: any, next: any) {
  try {
    const context = {
      url: req.path,
      method: req.method,
      user: req.user, // Assuming user is set by authentication middleware
      queryParams: req.query,
      headers: req.headers,
    };

    const isAllowed = await urlAccessControl.isAllowed(context);

    if (!isAllowed) {
      return res.status(403).json({
        error: "Access Denied",
        message: "You do not have permission to access this resource",
      });
    }

    next();
  } catch (error) {
    console.error("Security check failed:", error);
    res.status(500).json({
      error: "Internal Server Error",
      message: "Failed to process security rules",
    });
  }
}

// Example requests
async function demonstrateURLControl() {
  // Public access
  const publicContext = {
    url: "/api/public/data",
    method: "GET",
  };

  console.log("\nPublic access:");
  console.log("Result:", await urlAccessControl.isAllowed(publicContext));

  // Authenticated user accessing their profile
  const profileContext = {
    url: "/api/users/123/profile",
    method: "GET",
    user: {
      id: "123",
      roles: ["user"],
    },
  };

  console.log("\nUser accessing their profile:");
  console.log("Result:", await urlAccessControl.isAllowed(profileContext));

  // Admin access
  const adminContext = {
    url: "/api/admin/users",
    method: "GET",
    user: {
      id: "admin1",
      roles: ["admin"],
    },
  };

  console.log("\nAdmin accessing admin route:");
  console.log("Result:", await urlAccessControl.isAllowed(adminContext));

  // Internal service access
  const internalContext = {
    url: "/api/internal/metrics",
    method: "POST",
    user: {
      id: "service1",
      roles: ["internal-service"],
      permissions: ["api:internal:access"],
    },
  };

  console.log("\nInternal service access:");
  console.log("Result:", await urlAccessControl.isAllowed(internalContext));
}

demonstrateURLControl().catch(console.error);
