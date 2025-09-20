import { ACL } from "owasp-web-shield";

// Initialize ACL system
const acl = new ACL({
  defaultDeny: true,
  enableWildcards: true,
});

// Define some example rules
const rules = [
  // Allow users to read their own documents
  {
    allow: true,
    principal: { type: "user", id: "*" },
    resource: { type: "document", id: "*" },
    permissions: ["read"],
    conditions: {
      isOwner: true,
    },
  },

  // Allow editors to modify any document
  {
    allow: true,
    principal: { type: "role", id: "editor" },
    resource: { type: "document", id: "*" },
    permissions: ["read", "write", "update"],
  },

  // Allow admins full access to everything
  {
    allow: true,
    principal: { type: "role", id: "admin" },
    resource: { type: "*", id: "*" },
    permissions: "*",
    priority: 100,
  },

  // Allow public access to published documents
  {
    allow: true,
    principal: { type: "*", id: "*" },
    resource: { type: "document", id: "*" },
    permissions: ["read"],
    conditions: {
      isPublished: true,
    },
  },
];

// Add rules to ACL system
rules.forEach((rule) => acl.addRule(rule));

// Example usage
async function demonstrateACL() {
  // Test regular user access
  const userQuery = {
    principal: { type: "user", id: "user123" },
    resource: { type: "document", id: "doc1" },
    permission: "read",
    context: {
      isOwner: true,
    },
  };

  console.log("\nRegular user reading own document:");
  console.log("Result:", await acl.isAllowed(userQuery));

  // Test editor access
  const editorQuery = {
    principal: { type: "role", id: "editor" },
    resource: { type: "document", id: "doc1" },
    permission: "write",
  };

  console.log("\nEditor writing to document:");
  console.log("Result:", await acl.isAllowed(editorQuery));

  // Test public access to published document
  const publicQuery = {
    principal: { type: "user", id: "anonymous" },
    resource: { type: "document", id: "doc1" },
    permission: "read",
    context: {
      isPublished: true,
    },
  };

  console.log("\nPublic access to published document:");
  console.log("Result:", await acl.isAllowed(publicQuery));

  // Test admin access
  const adminQuery = {
    principal: { type: "role", id: "admin" },
    resource: { type: "document", id: "doc1" },
    permission: "delete",
  };

  console.log("\nAdmin deleting document:");
  console.log("Result:", await acl.isAllowed(adminQuery));
}

demonstrateACL().catch(console.error);
