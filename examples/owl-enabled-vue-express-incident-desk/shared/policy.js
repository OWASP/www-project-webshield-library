// Shared by the Express API (server/) and the Vue app (src/), so the UI's gates
// and the server's checks always agree. The server is still the authority:
// hiding a button in the UI is a convenience, enforcing the rule is the API's job.

/**
 * A01: RBAC roles, as `createOwlClient({ roles })` takes them. Permissions
 * are "action:resource". Per-incident checks use the resource
 * `incident:<id>`, so a wildcard such as `update:*` covers every incident,
 * and an ACL deny on one incident can still override it (see "lock").
 */
export const ROLES = {
  reporter: { permissions: ["read:*", "create:incidents"] },
  responder: { permissions: ["update:*", "note:*"], inherits: ["reporter"] },
  admin: { permissions: ["delete:*", "lock:*", "view:audit", "manage:integrations"], inherits: ["responder"] }
};

export const incidentResource = (id) => `incident:${id}`;

export const SEVERITIES = ["low", "medium", "high", "critical"];

/**
 * A04: the incident lifecycle, as `ThreatModelGuard` takes it. A closed
 * incident can't be reopened, so its history stays trustworthy.
 */
export const STATUS_TRANSITIONS = {
  open: ["investigating", "closed"],
  investigating: ["resolved", "open"],
  resolved: ["closed", "investigating"],
  closed: []
};

export const STATUS_LABELS = {
  open: "Open",
  investigating: "Investigating",
  resolved: "Resolved",
  closed: "Closed"
};

/** A03: `InputValidator` schemas, used by the API and for client-side hints. */
export const LOGIN_SCHEMA = {
  username: { required: true, type: "string", maxLength: 64 },
  password: { required: true, type: "string", maxLength: 256 }
};

export const INCIDENT_SCHEMA = {
  title: { required: true, type: "string", minLength: 4, maxLength: 120 },
  severity: { required: true, type: "string", pattern: /^(low|medium|high|critical)$/ },
  description: { required: true, type: "string", minLength: 1, maxLength: 5000 }
};

export const STATUS_SCHEMA = {
  status: { required: true, type: "string", pattern: /^(open|investigating|resolved|closed)$/ }
};

export const NOTE_SCHEMA = {
  text: { required: true, type: "string", minLength: 1, maxLength: 2000 }
};

export const LOCK_SCHEMA = {
  locked: { required: true, type: "boolean" }
};

export const WEBHOOK_SCHEMA = {
  url: { required: true, type: "string", maxLength: 2048 }
};
