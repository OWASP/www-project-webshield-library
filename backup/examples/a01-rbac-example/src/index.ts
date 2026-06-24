import { RBAC, Role, Subject, AccessRequest } from "owasp-web-shield";

// Initialize RBAC system
const rbac = new RBAC({ hierarchical: true });

// Define roles
const roles: Role[] = [
  {
    name: "user",
    permissions: [
      { action: "read", resource: "document" },
      { action: "read", resource: "profile" },
    ],
  },
  {
    name: "editor",
    permissions: [
      { action: "write", resource: "document" },
      { action: "update", resource: "document" },
    ],
    inheritFrom: ["user"],
  },
  {
    name: "admin",
    permissions: [
      { action: "delete", resource: "document" },
      { action: "manage", resource: "*" },
    ],
    inheritFrom: ["editor"],
  },
];

// Add roles to RBAC system
roles.forEach((role) => rbac.addRole(role));

// Register custom permission verifier for document access
rbac.registerPermissionVerifier("read", async (request: AccessRequest) => {
  if (request.resource.type === "document") {
    // Check if document is public or user is the owner
    const isPublic = request.resource.attributes?.isPublic ?? false;
    const isOwner = request.resource.attributes?.ownerId === request.subject.id;
    return isPublic || isOwner;
  }
  return true;
});

// Example usage
async function main() {
  // Create test users
  const regularUser: Subject = {
    id: "user123",
    roles: ["user"],
  };

  const editor: Subject = {
    id: "editor456",
    roles: ["editor"],
  };

  const admin: Subject = {
    id: "admin789",
    roles: ["admin"],
  };

  // Test different access scenarios
  const testScenarios = [
    {
      description: "Regular user reading public document",
      request: {
        subject: regularUser,
        action: "read",
        resource: {
          type: "document",
          id: "doc1",
          attributes: { isPublic: true },
        },
      },
    },
    {
      description: "Regular user trying to write document",
      request: {
        subject: regularUser,
        action: "write",
        resource: {
          type: "document",
          id: "doc1",
        },
      },
    },
    {
      description: "Editor updating document",
      request: {
        subject: editor,
        action: "update",
        resource: {
          type: "document",
          id: "doc1",
        },
      },
    },
    {
      description: "Admin deleting document",
      request: {
        subject: admin,
        action: "delete",
        resource: {
          type: "document",
          id: "doc1",
        },
      },
    },
  ];

  // Run test scenarios
  for (const scenario of testScenarios) {
    const result = await rbac.can(scenario.request);
    console.log(`\nScenario: ${scenario.description}`);
    console.log(`Result: ${result ? "Allowed" : "Denied"}`);
  }
}

main().catch(console.error);
