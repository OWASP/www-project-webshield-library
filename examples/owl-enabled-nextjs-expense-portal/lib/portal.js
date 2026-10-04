import { Agent, fetch as undiciFetch } from "undici";
import { createOwlClient, DependencyRiskScanner, DesignChecklist, SafeFetcher, SecurityLogger, SSRFGuard } from "@owasp-webshield/core";
import { assertHardened } from "@owasp-webshield/next";
import { createBankDetailsStore } from "./bank-details.js";
import { createClaimService } from "./claims.js";
import { NpmAuditProvider } from "./npm-audit-provider.js";
import { ROLES } from "./policy.js";
import { createRateLimiter } from "./rate-limit.js";
import { createSessionStore } from "./sessions.js";
import { createUserStore } from "./users.js";

/** A05: the settings this app actually runs with, checked at startup. */
export function runtimeConfig(env = process.env) {
  return {
    debug: env.OWL_DEBUG === "true",
    cors: { origin: "self" },
    cookies: { secure: true, httpOnly: true, sameSite: "Lax" }
  };
}

export const IMPLEMENTED_CONTROLS = [
  "server_side_authorization",
  "scoped_claim_visibility",
  "segregation_of_duties",
  "approval_limits",
  "duplicate_claim_detection",
  "password_hashing_pbkdf2",
  "login_lockout_and_rate_limit",
  "server_side_sessions",
  "csrf_double_submit_and_synchronizer",
  "input_validation_no_mass_assignment",
  "stored_html_sanitization",
  "encrypted_bank_details",
  "ssrf_guarded_receipt_import",
  "safe_file_download",
  "redacted_audit_log",
  "security_headers_csp",
  "startup_hardening_check"
];

/**
 * Builds every store and service. Options exist so tests can use fast password
 * hashing, a fixed clock and an offline DNS resolver.
 */
export function createPortal(options = {}) {
  const {
    env = process.env,
    kdfIterations = env.OWL_KDF_ITERATIONS ? Number(env.OWL_KDF_ITERATIONS) : undefined,
    sessionTtlMs = env.OWL_SESSION_TTL_MS ? Number(env.OWL_SESSION_TTL_MS) : undefined,
    guard = new SSRFGuard(),
    fetchImpl = undiciFetch,
    auditProvider = new NpmAuditProvider({ cwd: process.cwd() }),
    echoLogs = env.OWL_ECHO_LOGS === "true",
    now
  } = options;

  // A09: redaction-first logging into a ring buffer that the audit page reads.
  const logs = [];
  const logger = new SecurityLogger({
    sink: (entry) => {
      logs.push(entry);
      if (logs.length > 500) logs.shift();
      if (echoLogs) console.log(JSON.stringify(entry));
    }
  });

  // A05: refuse to start with a high-severity misconfiguration.
  const hardening = assertHardened(runtimeConfig(env), { logger });

  const owl = createOwlClient({ roles: ROLES });
  const bankDetails = createBankDetailsStore();

  return {
    logs,
    logger,
    hardening,
    owl,
    bankDetails,
    users: createUserStore({ kdfIterations, now }),
    sessions: createSessionStore({ ttlMs: sessionTtlMs, now }),
    claims: createClaimService({ owl, logger, bankDetails, now }),
    // A04/A07: failed sign-ins per client IP per minute (the per-account lockout is in users.js).
    signInLimiter: createRateLimiter({ limit: Number(env.OWL_SIGNIN_FAILURES_PER_MINUTE || 10), now }),
    // A10: every hop is re-validated and the socket only connects to the checked address.
    receiptFetcher: new SafeFetcher({ guard, fetchImpl, dispatcher: new Agent({ connect: { lookup: guard.createSafeLookup() } }) }),
    guard,
    scanner: new DependencyRiskScanner(auditProvider),
    checklist: new DesignChecklist(IMPLEMENTED_CONTROLS)
  };
}

/**
 * The process-wide portal. Next.js can load this module more than once (one
 * copy per route bundle, again after a dev-server reload), so the instance is
 * kept on globalThis to give every route the same in-memory data.
 */
export function portal() {
  globalThis.__owlExpensePortal ??= createPortal();
  return globalThis.__owlExpensePortal;
}
