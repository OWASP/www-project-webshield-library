// The portal's rules in one place, imported by the route handlers, the Server
// Actions and the pages, so a rule can't be enforced in one place and forgotten
// in another. Nothing here is secret.

/**
 * A01: RBAC roles, as `createOwlClient({ roles })` takes them. Permissions are
 * "action:scope". A claim belongs to the narrowest scope that contains it for
 * the viewer: their own claims, their team's, or anyone's (see `scopesFor()`).
 */
export const ROLES = {
  employee: { permissions: ["create:claims", "read:own-claims", "comment:own-claims", "attach:own-claims"] },
  manager: { permissions: ["read:team-claims", "comment:team-claims", "approve:team-claims"], inherits: ["employee"] },
  finance: {
    permissions: [
      "read:any-claims",
      "comment:any-claims",
      "approve:any-claims",
      "approve:large-claims",
      "pay:any-claims",
      "view:bank-details",
      "view:audit",
      "run:security-checks"
    ],
    inherits: ["employee"]
  }
};

/**
 * The scopes a claim falls into for `session`, narrowest first: your own claim
 * is also in your team and in "any". A permission on any of them applies.
 */
export function scopesFor(session, claim) {
  if (claim.ownerId === session.userId) return ["own-claims", "team-claims", "any-claims"];
  if (claim.team === session.metadata.team) return ["team-claims", "any-claims"];
  return ["any-claims"];
}

/** A04: managers approve up to this amount; above it needs `approve:large-claims` (finance). */
export const MANAGER_APPROVAL_LIMIT_CENTS = 100_000;
/** A04: at most this many claims waiting for a decision per employee. */
export const MAX_PENDING_PER_EMPLOYEE = 5;
/** A04: expenses older than this can't be claimed. */
export const MAX_EXPENSE_AGE_DAYS = 90;
export const MAX_AMOUNT_CENTS = 5_000_000;

/**
 * A04: the claim lifecycle, as `ThreatModelGuard` takes it. Rejected and paid
 * are final, so a paid claim can't be reopened and paid twice.
 */
export const STATUS_TRANSITIONS = {
  submitted: ["approved", "rejected"],
  approved: ["paid"],
  rejected: [],
  paid: []
};

/** Which permission moves a claim into each status. */
export const STATUS_PERMISSION = { approved: "approve", rejected: "approve", paid: "pay" };

export const CATEGORIES = ["travel", "meals", "lodging", "software", "equipment", "other"];

/** A03: `InputValidator` schemas. Amounts are strings so they never pass through a float. */
export const LOGIN_SCHEMA = {
  username: { required: true, type: "string", maxLength: 64 },
  password: { required: true, type: "string", maxLength: 256 }
};

export const CLAIM_SCHEMA = {
  merchant: { required: true, type: "string", minLength: 2, maxLength: 80 },
  amount: { required: true, type: "string", pattern: /^\d{1,5}(\.\d{2})?$/ },
  category: { required: true, type: "string", pattern: new RegExp(`^(${CATEGORIES.join("|")})$`) },
  spentOn: { required: true, type: "string", pattern: /^\d{4}-\d{2}-\d{2}$/ },
  description: { required: true, type: "string", minLength: 1, maxLength: 2000 }
};

export const STATUS_SCHEMA = {
  status: { required: true, type: "string", pattern: /^(approved|rejected|paid)$/ },
  reason: { type: "string", maxLength: 500 }
};

export const COMMENT_SCHEMA = {
  body: { required: true, type: "string", minLength: 1, maxLength: 4000 }
};

export const RECEIPT_SCHEMA = {
  url: { required: true, type: "string", maxLength: 2048 }
};

export const BANK_SCHEMA = {
  iban: { required: true, type: "string", minLength: 15, maxLength: 42 }
};
