import { existsSync } from "node:fs";
import { join } from "node:path";
import express from "express";
import { Agent, fetch as undiciFetch } from "undici";
import {
  createOwlClient,
  DependencyRiskScanner,
  DesignChecklist,
  InputSanitizer,
  SafeFetcher,
  SecurityLogger,
  SSRFGuard
} from "@owasp-webshield/core";
import {
  assertHardened,
  csrfProtection,
  errorHandler,
  guardOutboundUrl,
  issueCsrfToken,
  requireAuth,
  requirePermission,
  sanitizeBody,
  securityHeaders,
  validate
} from "@owasp-webshield/express";
import { serializeCookie } from "@owasp-webshield/node";
import {
  INCIDENT_SCHEMA,
  incidentResource,
  LOCK_SCHEMA,
  LOGIN_SCHEMA,
  NOTE_SCHEMA,
  ROLES,
  STATUS_SCHEMA,
  WEBHOOK_SCHEMA
} from "../shared/policy.js";
import { createIncidentStore } from "./incidents.js";
import { NpmAuditProvider } from "./npm-audit-provider.js";
import { createSessionStore } from "./sessions.js";
import { createUserStore } from "./users.js";

/**
 * CSP for the Vue app (all scripts and styles are built files served from this
 * origin). Images may come from https: because v-safe-html's moderate profile
 * keeps <img src="https://...">.
 */
export const APP_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' https: data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'"
].join("; ");

/** A05: the settings this server actually runs with, checked at boot. */
export function runtimeConfig(env = process.env) {
  return {
    debug: env.OWL_DEBUG === "true",
    cors: { origin: env.CORS_ORIGIN || "self" },
    cookies: { secure: true, httpOnly: true, sameSite: "Strict" }
  };
}

const IMPLEMENTED_CONTROLS = [
  "server_side_authorization",
  "per_incident_deny_override",
  "password_hashing_pbkdf2",
  "login_lockout",
  "server_side_sessions",
  "csrf_synchronizer_token",
  "input_validation",
  "stored_html_sanitization",
  "encrypted_private_notes",
  "ssrf_guarded_webhooks",
  "redacted_audit_log",
  "security_headers_csp",
  "startup_hardening_check"
];

/**
 * Builds the Express app. Options exist so tests can use fast password hashing,
 * short sessions and an offline DNS resolver; production uses the defaults.
 */
export function createIncidentDeskApp(options = {}) {
  const {
    config = runtimeConfig(),
    sessionTtlMs = 15 * 60_000,
    kdfIterations,
    distDir = null,
    guard = new SSRFGuard(),
    fetchImpl = undiciFetch,
    auditProvider = new NpmAuditProvider({ cwd: process.cwd() }),
    echoLogs = false
  } = options;

  // A09: redaction-first logging into an in-memory ring buffer the admin page reads.
  const logs = [];
  const logger = new SecurityLogger({
    sink: (entry) => {
      logs.push(entry);
      if (logs.length > 500) logs.shift();
      if (echoLogs) console.log(JSON.stringify(entry));
    }
  });

  // A05: refuse to start with a high-severity misconfiguration.
  const hardening = assertHardened(config, { logger });

  // A01: the same role definitions the Vue app uses for its gates.
  const owl = createOwlClient({ roles: ROLES });
  const users = createUserStore({ kdfIterations });
  const sessions = createSessionStore({ ttlMs: sessionTtlMs });
  const incidents = createIncidentStore();
  const moderate = new InputSanitizer("moderate");
  const scanner = new DependencyRiskScanner(auditProvider);
  const checklist = new DesignChecklist(IMPLEMENTED_CONTROLS);

  // A10: every webhook hop is re-validated, and the socket only connects to the
  // addresses the guard checked (no DNS-rebinding race between check and connect).
  const safeFetcher = new SafeFetcher({
    guard,
    fetchImpl,
    dispatcher: new Agent({ connect: { lookup: guard.createSafeLookup() } })
  });

  const app = express();
  app.disable("x-powered-by");
  app.use(securityHeaders({ "Content-Security-Policy": APP_CSP }));
  app.use(express.json({ limit: "32kb" }));

  const api = express.Router();

  // ---- Public: sign in -------------------------------------------------------
  api.post("/session", validate(LOGIN_SCHEMA, { allowUnknownFields: false }), (req, res) => {
    const user = users.verify(req.body.username, req.body.password);
    // A08: the CSRF token goes to the browser in the XSRF-TOKEN cookie (which
    // @owasp-webshield/vue's useSecureHttpClient sends back as X-CSRF-Token) and
    // is stored in the session, which is what the server checks it against.
    const csrfToken = issueCsrfToken(res);
    const { accessToken, expiresAt } = sessions.create(user, csrfToken);
    logger.info("auth.login", { userId: user.id });
    res.status(201).json({ accessToken, expiresAt, user });
  });

  // ---- Everything below needs a session and, for writes, its CSRF token -------
  api.use(requireAuth({ verifyToken: (token) => sessions.lookup(token) }));
  api.use(csrfProtection({ getExpectedToken: (req) => req.owl.session.metadata.csrfToken }));

  const byIncident = (req) => incidentResource(req.params.id);

  api.get("/session", (req, res) => {
    const { userId, roles, metadata } = req.owl.session;
    res.json({ user: { id: userId, name: metadata.name, roles }, expiresAt: metadata.expiresAt });
  });

  api.delete("/session", (req, res) => {
    sessions.destroy(req.owl.session.metadata.accessToken);
    res.setHeader("Set-Cookie", serializeCookie("XSRF-TOKEN", "", { httpOnly: false, maxAge: 0 }));
    logger.info("auth.logout", { userId: req.owl.session.userId });
    res.status(204).end();
  });

  api.get("/incidents", requirePermission("read", "incidents", owl), (req, res) => {
    res.json(incidents.list());
  });

  api.post(
    "/incidents",
    requirePermission("create", "incidents", owl),
    validate(INCIDENT_SCHEMA, { allowUnknownFields: false }),
    // A03: stored rich text is sanitized once here, and again by v-safe-html when
    // rendered, so any other consumer of this API gets safe HTML too.
    sanitizeBody(["description"], { sanitizer: moderate }),
    (req, res) => {
      const incident = incidents.create(req.body, req.owl.session);
      logger.info("incident.created", { id: incident.id, by: req.owl.session.userId });
      res.status(201).json(incident);
    }
  );

  api.get("/incidents/:id", requirePermission("read", byIncident, owl), (req, res) => {
    res.json(incidents.get(req.params.id));
  });

  api.patch(
    "/incidents/:id/status",
    requirePermission("update", byIncident, owl),
    validate(STATUS_SCHEMA, { allowUnknownFields: false }),
    (req, res) => {
      const incident = incidents.transition(req.params.id, req.body.status);
      logger.info("incident.status", { id: incident.id, status: incident.status, by: req.owl.session.userId });
      res.json(incident);
    }
  );

  api.get("/incidents/:id/notes", requirePermission("note", byIncident, owl), (req, res) => {
    res.json(incidents.readNotes(req.params.id));
  });

  api.post(
    "/incidents/:id/notes",
    requirePermission("note", byIncident, owl),
    validate(NOTE_SCHEMA, { allowUnknownFields: false }),
    (req, res) => {
      // A02: encrypted at rest. A09: the note text is logged under a key the
      // logger redacts, to show that it never reaches the log in clear.
      const count = incidents.addNote(req.params.id, req.body.text, req.owl.session);
      logger.info("incident.note_added", { id: req.params.id, by: req.owl.session.userId, secretNote: req.body.text });
      res.status(201).json({ noteCount: count });
    }
  );

  api.put(
    "/incidents/:id/lock",
    requirePermission("lock", byIncident, owl),
    validate(LOCK_SCHEMA, { allowUnknownFields: false }),
    (req, res) => {
      // A01: an ACL deny on this one incident overrides every role's RBAC grant,
      // admins included, until it is unlocked.
      const effect = req.body.locked ? "deny" : "allow";
      owl.aclManager.setPolicy(byIncident(req), "update", effect);
      owl.aclManager.setPolicy(byIncident(req), "note", effect);
      const incident = incidents.setLocked(req.params.id, req.body.locked);
      logger.info(req.body.locked ? "incident.locked" : "incident.unlocked", { id: incident.id, by: req.owl.session.userId });
      res.json(incident);
    }
  );

  api.delete("/incidents/:id", requirePermission("delete", byIncident, owl), (req, res) => {
    incidents.remove(req.params.id);
    logger.warn("incident.deleted", { id: req.params.id, by: req.owl.session.userId });
    res.status(204).end();
  });

  // ---- Admin ----------------------------------------------------------------------
  api.get("/admin/audit", requirePermission("view", "audit", owl), (req, res) => {
    res.json(logs.slice(-200).reverse());
  });

  api.get("/admin/security-report", requirePermission("view", "audit", owl), (req, res) => {
    res.json({
      hardening,
      designChecklist: { required: IMPLEMENTED_CONTROLS, ...checklist.validate(IMPLEMENTED_CONTROLS) }
    });
  });

  api.post("/admin/dependency-scan", requirePermission("view", "audit", owl), async (req, res) => {
    // A06: one `npm audit` run; findings at "high" or above fail the policy.
    const { pass, blocked, results } = await scanner.passesPolicy("high");
    res.json({ passes: pass, blocked, findings: results });
  });

  api.post(
    "/admin/webhook-test",
    requirePermission("manage", "integrations", owl),
    validate(WEBHOOK_SCHEMA, { allowUnknownFields: false }),
    guardOutboundUrl((req) => req.body.url, { guard }),
    async (req, res) => {
      const target = req.owl.outboundUrl.href;
      try {
        const response = await safeFetcher.fetch(target, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type: "owl.incident_desk.test" }),
          signal: AbortSignal.timeout(5000)
        });
        logger.info("webhook.test", { target, status: response.status });
        res.json({ delivered: true, status: response.status });
      } catch (error) {
        if (error?.code === "SSRF_BLOCKED") throw error; // a redirect to a blocked target
        logger.warn("webhook.failed", { target, reason: String(error?.message || error) });
        res.status(502).json({ error: "delivery_failed" });
      }
    }
  );

  app.use("/api", api);

  // ---- The built Vue app (npm start) --------------------------------------------
  if (distDir && existsSync(distDir)) {
    app.use(express.static(distDir, { index: false }));
    app.use((req, res, next) => {
      if (req.method !== "GET" || req.path.startsWith("/api/")) return next();
      res.sendFile(join(distDir, "index.html"));
    });
  }

  // A09: maps SecurityErrors to 400/401/403, hides 5xx details, logs every failure.
  app.use(errorHandler({ logger }));

  return { app, logs, logger, sessions, incidents, owl };
}
