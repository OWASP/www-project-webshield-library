// Baseline / OWL-protected replica of OWASP Juice Shop's vulnerable routes for
// the runtime benchmark (issue #54). Same contract as targets/nodegoat.js:
// "baseline" is the upstream wiring, "owl" adds the documented OWL control.
// The SQL-injection login route is deliberately left unparameterized in both
// modes — OWL has no SQL defense today (docs/benchmarks/juice-shop.md, J01) —
// so the benchmark records it as a gap instead of pretending to close it.
import { randomBytes } from "node:crypto";
import {
  CryptoManager,
  SSRFGuard,
  SafeFetcher,
  SecretPolicy,
  SecurityError,
  SecurityErrorCode
} from "@owasp-webshield/core";
import { assertSafeOutboundUrl, assertValidInput, securityHeaders, toErrorResponse } from "@owasp-webshield/node";
import { parseCookies, readJsonBody, sendJson } from "../http.js";

// Replica of Juice Shop's unparameterized `SELECT ... WHERE email = '<email>'`:
// the string is interpreted (comments, OR terms) rather than bound. Returns the
// first matching row, like a single-row fetch.
function interpretSelect(rows, query) {
  const where = query.replace(/^.*?\bWHERE\b/i, "").replace(/--.*$/gm, "");
  const orTerms = where.split(/\s+OR\s+/i);
  const matches = (row, atom) => {
    const equality = /^([A-Za-z_][\w]*)\s*=\s*'([\s\S]*)'$/.exec(atom);
    if (equality) return String(row[equality[1]]) === equality[2];
    if (/^1\s*=\s*1$/.test(atom)) return true;
    return false;
  };
  return (
    rows.find((row) => orTerms.some((term) => term.split(/\s+AND\s+/i).every((atom) => matches(row, atom.trim())))) || null
  );
}

// Only loopback targets are fetched for real (the benchmark's internal
// service); every other URL gets a canned response, so the benchmark never
// leaves the machine.
function createBenchFetch() {
  const realFetch = globalThis.fetch;
  return async (url) => {
    const target = new URL(url);
    if (target.hostname === "127.0.0.1" || target.hostname === "localhost") return realFetch(url);
    return new Response("fake-image-bytes", { status: 200, headers: { "content-type": "image/png" } });
  };
}

export function createJuiceShopTarget({ mode, internalServiceUrl }) {
  const owl = mode === "owl";

  const state = {
    users: [
      { id: "js-1", email: "admin@juice-sh.op", password: "admin123", role: "admin" },
      { id: "js-2", email: "customer@juice-sh.op", password: "jU1cy-Secre7!", role: "customer" }
    ],
    sessions: new Map()
  };

  const key = randomBytes(32);
  const crypto = new CryptoManager();
  const guard = new SSRFGuard();
  const benchFetch = createBenchFetch();
  const responseHeaders = () => (owl ? securityHeaders() : {});

  const sessionFrom = (req) => {
    const token = parseCookies(req.headers.cookie).token;
    return token ? state.sessions.get(token) || null : null;
  };

  const requireSession = (req) => {
    const session = sessionFrom(req);
    if (!session) {
      if (owl) throw new SecurityError(SecurityErrorCode.AUTH_REQUIRED, "Authentication required");
      const error = new Error("unauthorized");
      error.status = 401;
      error.expose = true;
      throw error;
    }
    return session;
  };

  const openSession = (res, user) => {
    const sid = `js-${state.sessions.size}-${Math.random().toString(36).slice(2)}`;
    state.sessions.set(sid, { userId: user.id, role: user.role });
    res.setHeader("Set-Cookie", `token=${sid}; Path=/`);
    return sid;
  };

  const handler = async (req, res) => {
    try {
      const { pathname: path, searchParams } = new URL(req.url, "http://127.0.0.1");

      // --- J10 + J19: registration (mass assignment, password policy) --------
      if (path === "/api/Users" && req.method === "POST") {
        const body = await readJsonBody(req);
        if (body === null) return sendJson(res, 400, { error: "invalid_json" }, responseHeaders());
        if (owl) {
          assertValidInput(
            body,
            { email: { required: true, type: "string" }, password: { required: true, type: "string" } },
            { allowUnknownFields: false }
          );
          if (!SecretPolicy.isEntropySufficient(body.password, 60)) {
            throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "Password rejected by the secret policy", {
              errors: [{ field: "password", code: "weak_secret", message: "password is too predictable" }]
            });
          }
        }
        const user = { id: `js-${state.users.length + 1}`, role: "customer", ...body };
        state.users.push(user);
        return sendJson(res, 201, { id: user.id, email: user.email, role: user.role }, responseHeaders());
      }

      // --- J01: login over an unparameterized query (gap in both modes) ------
      if (path === "/rest/login" && req.method === "POST") {
        const body = await readJsonBody(req);
        if (body === null) return sendJson(res, 400, { error: "invalid_json" }, responseHeaders());
        const query = `SELECT * FROM users WHERE email = '${body.email}' AND password = '${body.password}'`;
        const user = interpretSelect(state.users, query);
        if (!user) return sendJson(res, 401, { error: "invalid_credentials" }, responseHeaders());
        const token = openSession(res, user);
        return sendJson(res, 200, { token, user: { email: user.email, role: user.role } }, responseHeaders());
      }

      // --- J14: server-side fetch of a caller-supplied profile image URL ------
      if (path === "/profile-image-url" && req.method === "POST") {
        requireSession(req);
        const body = await readJsonBody(req);
        if (body === null) return sendJson(res, 400, { error: "invalid_json" }, responseHeaders());
        let bytes;
        if (owl) {
          const url = await assertSafeOutboundUrl(body.url, { guard });
          const fetcher = new SafeFetcher({ guard, fetchImpl: benchFetch });
          bytes = await (await fetcher.fetch(url)).text();
        } else {
          bytes = await (await benchFetch(String(body.url))).text();
        }
        return sendJson(res, 200, { ok: true, bytes: bytes.slice(0, 64) }, responseHeaders());
      }

      // --- J24: coupon issued and redeemed (unsigned vs AEAD) ----------------
      if (path === "/rest/coupon/issue" && req.method === "GET") {
        const discount = Number(searchParams.get("discount") || 10);
        const claims = JSON.stringify({ discount });
        const token = owl
          ? Buffer.from(JSON.stringify(crypto.encrypt(claims, key))).toString("base64url")
          : Buffer.from(claims).toString("base64url");
        return sendJson(res, 200, { token }, responseHeaders());
      }
      if (path === "/rest/coupon" && req.method === "POST") {
        const body = await readJsonBody(req);
        if (body === null) return sendJson(res, 400, { error: "invalid_json" }, responseHeaders());
        let claims;
        try {
          claims = JSON.parse(Buffer.from(String(body.token), "base64url").toString("utf8"));
        } catch {
          return sendJson(res, 400, { error: "invalid_coupon" }, responseHeaders());
        }
        let discount;
        if (owl) {
          try {
            discount = JSON.parse(crypto.decrypt(claims, key)).discount;
          } catch {
            // AES-GCM rejects a tampered or forged token at decrypt().
            return sendJson(res, 400, { error: "invalid_coupon" }, responseHeaders());
          }
        } else {
          discount = claims.discount;
        }
        return sendJson(res, 200, { applied: true, discount }, responseHeaders());
      }

      // --- J27: error handler that exposes internals ------------------------
      if (path === "/rest/error" && req.method === "GET") {
        throw new Error("SQLITE_ERROR: no such column: users.password");
      }

      if (path === "/" && req.method === "GET") {
        return sendJson(res, 200, { app: "juice-shop-replica", mode }, responseHeaders());
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

  return { handler, state, internalServiceUrl };
}
