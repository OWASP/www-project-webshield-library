// Baseline / OWL-protected replica of OWASP NodeGoat's vulnerable routes for
// the runtime benchmark (issue #54). Each route mirrors one NodeGoat weakness
// documented in docs/benchmarks/nodegoat.md; `mode` picks the target:
//
//   "baseline" — the upstream wiring (no OWL), which the attacks must exploit.
//   "owl"      — the same routes with the documented OWL control applied.
//
// Where OWL has no control (IDOR ownership, brute force), "owl" keeps the
// upstream behaviour on purpose: that is the coverage gap the benchmark
// measures instead of hiding.
import {
  CSRFTokenManager,
  InputSanitizer,
  RBACManager,
  SecurityError,
  SecurityErrorCode,
  SecurityLogger
} from "@owasp-webshield/core";
import {
  assertPermission,
  assertValidInput,
  sanitizeFields,
  securityHeaders,
  toErrorResponse,
  verifyCsrf
} from "@owasp-webshield/node";
import { parseCookies, readJsonBody, sendJson } from "../http.js";

function sessionFrom(req, state) {
  const sid = parseCookies(req.headers.cookie).sid;
  return sid ? state.sessions.get(sid) || null : null;
}

function openSession(res, user, state) {
  const sid = `ng-${state.sessions.size}-${Math.random().toString(36).slice(2)}`;
  const session = { userId: user.id, roles: [user.role], email: user.email, csrf: new CSRFTokenManager().rotateToken() };
  state.sessions.set(sid, session);
  res.setHeader("Set-Cookie", `sid=${sid}; Path=/; HttpOnly`);
  return session;
}

export function createNodeGoatTarget(mode) {
  const owl = mode === "owl";

  const state = {
    users: [
      { id: "u1", name: "alice", email: "alice@nodegoat.local", password: "S3cure-ish!", role: "user" },
      { id: "u2", name: "admin", email: "admin@nodegoat.local", password: "C0rrect-Horse-Battery-9", role: "admin" },
      { id: "u3", name: "bob", email: "bob@nodegoat.local", password: "bob-password-1", role: "user" },
      // Owns no data: the CSRF scenario mutates her e-mail address, so it gets
      // a dedicated victim and the scenarios that need a stable session keep
      // using alice.
      { id: "u4", name: "carol", email: "carol@nodegoat.local", password: "Carol-Passw0rd!", role: "user" }
    ],
    allocations: [
      { userId: "u1", label: "salary", amount: 110 },
      { userId: "u1", label: "savings", amount: 6 },
      { userId: "u2", label: "contract", amount: 550 }
    ],
    memos: [],
    sessions: new Map(),
    logText: ""
  };

  const rbac = new RBACManager();
  rbac.defineRole("user", ["read:allocations", "read:memos", "write:memos", "read:profile", "update:profile"]);
  rbac.defineRole("admin", ["*"]);

  const logger = new SecurityLogger({
    sink: (entry) => {
      state.logText += `${JSON.stringify(entry)}\n`;
    }
  });

  const responseHeaders = () => (owl ? securityHeaders() : {});

  const requireSession = (req) => {
    const session = sessionFrom(req, state);
    if (!session) {
      if (owl) throw new SecurityError(SecurityErrorCode.AUTH_REQUIRED, "Authentication required");
      const error = new Error("unauthorized");
      error.status = 401;
      error.expose = true;
      throw error;
    }
    return session;
  };

  const handler = async (req, res) => {
    try {
      const { pathname: path, searchParams } = new URL(req.url, "http://127.0.0.1");

      // --- A07/#3: login (log injection target for unknown users) -------------
      if (path === "/login" && req.method === "POST") {
        const body = await readJsonBody(req);
        if (body === null) return sendJson(res, 400, { error: "invalid_json" }, responseHeaders());
        const user = state.users.find((candidate) => candidate.email === body.email);
        if (!user || user.password !== body.password) {
          if (!user) {
            if (owl) logger.warn("auth.login_unknown_user", { userName: String(body.email) });
            else state.logText += `login failed for ${body.email}\n`;
          }
          return sendJson(res, 401, { error: "invalid_credentials" }, responseHeaders());
        }
        const session = openSession(res, user, state);
        return sendJson(
          res,
          200,
          { user: { id: user.id, name: user.name, role: user.role }, csrfToken: session.csrf },
          responseHeaders()
        );
      }

      // --- A01/#14: benefits is admin-only upstream, but the check was never wired ---
      if (path === "/benefits" && req.method === "GET") {
        const session = requireSession(req);
        if (owl) assertPermission({ session, action: "read", resource: "benefits" }, { rbacManager: rbac });
        return sendJson(res, 200, { benefits: ["health", "dental", "401k"] }, responseHeaders());
      }

      // --- A01/#13: allocations are fetched by user id with no ownership check ---
      const allocation = /^\/allocations\/([^/]+)$/.exec(path);
      if (allocation && req.method === "GET") {
        const session = requireSession(req);
        if (owl) assertPermission({ session, action: "read", resource: "allocations" }, { rbacManager: rbac });
        // Gap: the OWL-wired build only checks the role. `params.userId` is
        // never compared with `session.userId`, exactly as in nodegoat.md #13.
        const rows = state.allocations.filter((row) => row.userId === allocation[1]);
        return sendJson(res, 200, { allocations: rows }, responseHeaders());
      }

      // --- A03/#2: `$where` string built from the unvalidated threshold ------
      if (path === "/allocations" && req.method === "GET") {
        const session = requireSession(req);
        const threshold = searchParams.get("threshold");
        if (owl) {
          assertValidInput({ threshold }, { threshold: { required: true, type: "string", pattern: /^\d{1,3}$/ } });
        }
        const own = state.allocations.filter((row) => row.userId === session.userId);
        // Replica of allocations-dao.getByUserIdAndThreshold: the threshold is
        // spliced into a JavaScript expression evaluated per document.
        const filtered = own.filter((row) => {
          const predicate = new Function(...Object.keys(row), `return amount > ${threshold};`);
          return predicate(...Object.values(row));
        });
        return sendJson(res, 200, { allocations: filtered }, responseHeaders());
      }

      // --- A01/#17: state-changing form with the CSRF check disabled ----------
      if (path === "/profile" && req.method === "POST") {
        const session = requireSession(req);
        if (owl) await verifyCsrf(req, { getExpectedToken: async () => session.csrf });
        const body = await readJsonBody(req);
        if (body === null) return sendJson(res, 400, { error: "invalid_json" }, responseHeaders());
        const user = state.users.find((candidate) => candidate.id === session.userId);
        if (typeof body.email === "string") {
          user.email = body.email;
          session.email = body.email;
        }
        return sendJson(res, 200, { email: user.email }, responseHeaders());
      }

      // --- A03/#1: server-side code injection through the contribution amount --
      if (path === "/contributions" && req.method === "POST") {
        requireSession(req);
        const body = await readJsonBody(req);
        if (body === null) return sendJson(res, 400, { error: "invalid_json" }, responseHeaders());
        if (owl) {
          assertValidInput(body, { preTax: { required: true, type: "string", pattern: /^\d{1,2}$/ } });
        }
        // NodeGoat's handleContributionsUpdate: eval("1+" + preTax).
        const total = eval(`1+${body.preTax}`);
        return sendJson(res, 200, { total }, responseHeaders());
      }

      // --- A03/#4: memo stored and served without sanitization ---------------
      if (path === "/memos" && req.method === "POST") {
        requireSession(req);
        const body = await readJsonBody(req);
        if (body === null) return sendJson(res, 400, { error: "invalid_json" }, responseHeaders());
        const stored = owl
          ? sanitizeFields(body, ["memo"], { sanitizer: new InputSanitizer("moderate") }).memo
          : body.memo;
        state.memos.push(String(stored));
        return sendJson(res, 201, { memo: stored }, responseHeaders());
      }
      if (path === "/memos" && req.method === "GET") {
        requireSession(req);
        return sendJson(res, 200, { memos: state.memos }, responseHeaders());
      }

      if (path === "/" && req.method === "GET") {
        return sendJson(res, 200, { app: "nodegoat-replica", mode }, responseHeaders());
      }

      return sendJson(res, 404, { error: "not_found" }, responseHeaders());
    } catch (error) {
      if (owl) {
        const mapped = toErrorResponse(error);
        sendJson(res, mapped.status, mapped.body, { ...responseHeaders(), ...mapped.headers });
      } else if (error.status) {
        sendJson(res, error.status, { error: error.message }, responseHeaders());
      } else {
        sendJson(res, 500, { error: error.message, stack: error.stack }, responseHeaders());
      }
    }
  };

  return { handler, state };
}
