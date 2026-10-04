import { InputSanitizer, SecurityError, SecurityErrorCode, ThreatModelGuard } from "@owasp-webshield/core";
import { assertValidInput, checkPermission } from "@owasp-webshield/next";
import {
  CLAIM_SCHEMA,
  COMMENT_SCHEMA,
  MANAGER_APPROVAL_LIMIT_CENTS,
  MAX_AMOUNT_CENTS,
  MAX_EXPENSE_AGE_DAYS,
  MAX_PENDING_PER_EMPLOYEE,
  scopesFor,
  STATUS_PERMISSION,
  STATUS_SCHEMA,
  STATUS_TRANSITIONS
} from "./policy.js";

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * 404 rather than 403 for a claim the caller may not read: claim ids are
 * sequential, and a 403 would confirm that the id exists (and invite guessing).
 */
function notFound() {
  return Object.assign(new Error("No such claim"), { status: 404, expose: true });
}

function invalid(field, message) {
  return new SecurityError(SecurityErrorCode.INVALID_INPUT, message, { errors: [{ field, code: "rule", message }] });
}

/** "1234.50" -> 123450, without passing through a float. */
export function toCents(amount) {
  const [whole, fraction = "00"] = amount.split(".");
  return Number(whole) * 100 + Number(fraction);
}

export const formatCents = (cents) => `$${(cents / 100).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

/**
 * The claims service. Route handlers, Server Actions and pages all go through
 * it, and it checks the caller's access on every call, so no entry point can
 * skip a rule.
 *
 * - A01: what a caller can see and do follows the RBAC scopes in policy.js;
 *   a claim you can't read is "not found".
 * - A03: input is validated against the schemas with unknown fields rejected
 *   (no `status` or `ownerId` smuggled into a new claim); comments are stored as
 *   sanitized HTML.
 * - A04: the lifecycle, segregation of duties (nobody decides on their own
 *   claim), the manager approval limit, a cap on pending claims, duplicate
 *   detection and an expense date window.
 * - A09: every decision and every denial is logged.
 */
export function createClaimService({ owl, logger, bankDetails, now = () => Date.now() }) {
  const claims = new Map();
  const sanitizer = new InputSanitizer("moderate");
  let nextId = 1;

  const lifecycle = new ThreatModelGuard({
    transitions: STATUS_TRANSITIONS,
    abuseRules: [
      {
        id: "self_approval",
        message: "You can't approve, reject or pay your own claim.",
        check: (ctx) => ctx.actorId !== ctx.ownerId
      }
    ]
  });

  const submission = new ThreatModelGuard({
    abuseRules: [
      {
        id: "too_many_pending",
        message: `You already have ${MAX_PENDING_PER_EMPLOYEE} claims waiting for a decision.`,
        check: (ctx) => ctx.pending < MAX_PENDING_PER_EMPLOYEE
      },
      {
        id: "duplicate_claim",
        message: "This looks like a claim you already submitted (same merchant, amount and date).",
        check: (ctx) => !ctx.duplicate
      }
    ]
  });

  function can(session, action, claim) {
    return scopesFor(session, claim).some((scope) => checkPermission({ session, action, resource: scope }, owl).allowed);
  }

  function deny(session, action, claim, message) {
    logger.warn("security.access_denied", { userId: session.userId, action, claimId: claim?.id });
    return new SecurityError(SecurityErrorCode.ACCESS_DENIED, message);
  }

  /** The claim, if `session` may read it; "not found" otherwise. */
  function readable(session, id) {
    const claim = claims.get(String(id));
    if (!claim) throw notFound();
    if (!can(session, "read", claim)) {
      deny(session, "read", claim, "Not allowed");
      throw notFound();
    }
    return claim;
  }

  const view = (session, claim) => {
    const { receipt, comments, ...rest } = claim;
    return {
      ...rest,
      amount: formatCents(claim.amountCents),
      comments,
      receipt: receipt && { contentType: receipt.contentType, size: receipt.size, sha256: receipt.sha256, sourceHost: receipt.sourceHost },
      allowed: {
        comment: can(session, "comment", claim),
        attach: claim.status === "submitted" && can(session, "attach", claim),
        approve: nextStates(session, claim).includes("approved"),
        reject: nextStates(session, claim).includes("rejected"),
        pay: nextStates(session, claim).includes("paid"),
        viewBankDetails: claim.status === "approved" && checkPermission({ session, action: "view", resource: "bank-details" }, owl).allowed
      }
    };
  };

  /** The statuses `session` may move `claim` to now; the UI offers only these. */
  function nextStates(session, claim) {
    return STATUS_TRANSITIONS[claim.status].filter((status) => {
      try {
        assertDecision(session, claim, status);
        return true;
      } catch {
        return false;
      }
    });
  }

  function assertDecision(session, claim, status) {
    const action = STATUS_PERMISSION[status];
    if (!can(session, action, claim)) throw new SecurityError(SecurityErrorCode.ACCESS_DENIED, `Not allowed to ${action} this claim`);
    if (!lifecycle.validateTransition(claim.status, status).valid) {
      throw invalid("status", `A ${claim.status} claim can't become ${status}`);
    }
    const abuse = lifecycle.evaluateAbuseCase({ actorId: session.userId, ownerId: claim.ownerId });
    if (!abuse.valid) throw new SecurityError(SecurityErrorCode.ACCESS_DENIED, abuse.violations[0].message, { violations: abuse.violations });
    if (
      status === "approved" &&
      claim.amountCents > MANAGER_APPROVAL_LIMIT_CENTS &&
      !checkPermission({ session, action: "approve", resource: "large-claims" }, owl).allowed
    ) {
      throw new SecurityError(SecurityErrorCode.ACCESS_DENIED, `Claims over ${formatCents(MANAGER_APPROVAL_LIMIT_CENTS)} need finance approval`);
    }
    if (status === "paid" && !bankDetails.masked(claim.ownerId)) {
      throw invalid("status", "The employee hasn't added a payout account yet");
    }
  }

  return {
    list(session) {
      return [...claims.values()]
        .filter((claim) => can(session, "read", claim))
        .sort((a, b) => b.createdAt - a.createdAt)
        .map((claim) => ({ ...view(session, claim), comments: undefined, commentCount: claim.comments.length }));
    },

    get(session, id) {
      return view(session, readable(session, id));
    },

    create(session, input) {
      if (!checkPermission({ session, action: "create", resource: "claims" }, owl).allowed) {
        throw deny(session, "create", null, "Not allowed to submit claims");
      }
      const data = assertValidInput(input, CLAIM_SCHEMA, { allowUnknownFields: false });

      const amountCents = toCents(data.amount);
      if (amountCents <= 0 || amountCents > MAX_AMOUNT_CENTS) throw invalid("amount", `The amount must be between $0.01 and ${formatCents(MAX_AMOUNT_CENTS)}`);

      const spent = Date.parse(`${data.spentOn}T00:00:00Z`);
      if (Number.isNaN(spent) || new Date(spent).toISOString().slice(0, 10) !== data.spentOn) throw invalid("spentOn", "That isn't a valid date");
      if (spent > now()) throw invalid("spentOn", "The expense date can't be in the future");
      if (spent < now() - MAX_EXPENSE_AGE_DAYS * DAY_MS) throw invalid("spentOn", `Expenses older than ${MAX_EXPENSE_AGE_DAYS} days can't be claimed`);

      const own = [...claims.values()].filter((claim) => claim.ownerId === session.userId);
      const merchant = data.merchant.trim();
      const duplicate = own.find(
        (claim) =>
          claim.status !== "rejected" &&
          claim.amountCents === amountCents &&
          claim.spentOn === data.spentOn &&
          claim.merchant.toLowerCase() === merchant.toLowerCase()
      );
      const abuse = submission.evaluateAbuseCase({ pending: own.filter((claim) => claim.status === "submitted").length, duplicate });
      if (!abuse.valid) {
        logger.warn("claim.rejected_on_submit", { userId: session.userId, rule: abuse.violations[0].id, duplicateOf: duplicate?.id });
        throw new SecurityError(SecurityErrorCode.INVALID_INPUT, abuse.violations[0].message, {
          errors: [{ field: "merchant", code: abuse.violations[0].id, message: abuse.violations[0].message }]
        });
      }

      const id = String(nextId++);
      const claim = {
        id,
        merchant,
        amountCents,
        category: data.category,
        spentOn: data.spentOn,
        // A03: the description is plain text (React escapes it); only comments allow markup.
        description: data.description,
        status: "submitted",
        ownerId: session.userId,
        ownerName: session.metadata.name,
        team: session.metadata.team,
        history: [{ status: "submitted", by: session.metadata.name, at: now() }],
        comments: [],
        receipt: null,
        createdAt: now()
      };
      claims.set(id, claim);
      logger.info("claim.submitted", { id, userId: session.userId, amountCents });
      return view(session, claim);
    },

    setStatus(session, id, input) {
      const claim = readable(session, id);
      const { status, reason } = assertValidInput(input, STATUS_SCHEMA, { allowUnknownFields: false });
      try {
        assertDecision(session, claim, status);
      } catch (error) {
        logger.warn("security.decision_denied", { userId: session.userId, claimId: claim.id, status, message: error.message });
        throw error;
      }
      claim.status = status;
      const entry = { status, by: session.metadata.name, at: now() };
      if (reason) entry.reason = reason;
      if (status === "paid") entry.paidTo = bankDetails.masked(claim.ownerId);
      claim.history.push(entry);
      logger.info(`claim.${status}`, { id: claim.id, by: session.userId });
      return view(session, claim);
    },

    addComment(session, id, input) {
      const claim = readable(session, id);
      if (!can(session, "comment", claim)) throw deny(session, "comment", claim, "Not allowed to comment on this claim");
      const { body } = assertValidInput(input, COMMENT_SCHEMA, { allowUnknownFields: false });
      // A03: stored sanitized, so every reader of this data gets safe HTML.
      const comment = { author: session.metadata.name, body: sanitizer.sanitizeHTML(body), at: now() };
      claim.comments.push(comment);
      logger.info("claim.comment_added", { id: claim.id, by: session.userId });
      return comment;
    },

    attachReceipt(session, id, receipt) {
      const claim = readable(session, id);
      if (claim.status !== "submitted" || !can(session, "attach", claim)) {
        throw deny(session, "attach", claim, "Only the owner can attach a receipt, before the claim is decided");
      }
      claim.receipt = receipt;
      logger.info("claim.receipt_attached", { id: claim.id, by: session.userId, sourceHost: receipt.sourceHost, sha256: receipt.sha256 });
      return view(session, claim).receipt;
    },

    /** Readability is checked first, so this can't fetch another user's file. */
    receipt(session, id) {
      const claim = readable(session, id);
      if (!claim.receipt) throw notFound();
      return { ...claim.receipt, filename: `claim-${claim.id}-receipt.${claim.receipt.extension}` };
    },

    /** A02/A09: the full payout account for finance, audited on every read. */
    payoutAccount(session, id) {
      const claim = readable(session, id);
      if (!view(session, claim).allowed.viewBankDetails) throw deny(session, "view_bank_details", claim, "Not allowed to see payout details");
      logger.warn("bank_details.viewed", { claimId: claim.id, ownerId: claim.ownerId, by: session.userId });
      return bankDetails.reveal(claim.ownerId);
    }
  };
}
