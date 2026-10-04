/**
 * @jest-environment node
 */
import { describe, expect, test } from "@jest/globals";
import { createOwlClient, SecurityLogger, SSRFGuard } from "@owasp-webshield/core";
import {
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

// Minimal stand-ins for Express's req/res and its middleware dispatch: error
// handlers are the 4-argument functions, `next(err)` skips to the next one.
function createRes() {
  const headers = new Map();
  return {
    statusCode: 200,
    headersSent: false,
    body: undefined,
    setHeader(name, value) {
      headers.set(name.toLowerCase(), value);
    },
    getHeader(name) {
      return headers.get(name.toLowerCase());
    },
    removeHeader(name) {
      headers.delete(name.toLowerCase());
    },
    end(payload) {
      this.headersSent = true;
      this.body = payload === undefined ? undefined : JSON.parse(payload);
      this.onEnd?.();
    }
  };
}

function run(chain, { method = "GET", url = "/", headers = {}, body, params = {}, query = {} } = {}) {
  const req = { method, url, headers, body, params, query };
  const res = createRes();
  return new Promise((resolve) => {
    let index = 0;
    res.onEnd = () => resolve({ req, res });
    const next = (error) => {
      const layer = chain[index++];
      if (!layer) {
        resolve({ req, res, unhandled: error });
        return;
      }
      const isErrorHandler = layer.length === 4;
      if (error) {
        if (isErrorHandler) layer(error, req, res, next);
        else next(error);
      } else if (isErrorHandler) {
        next();
      } else {
        layer(req, res, next);
      }
    };
    next();
  });
}

const ok = (req, res) => {
  res.statusCode = 200;
  res.end(JSON.stringify({ ok: true, session: req.owl?.session, body: req.body }));
};

const owl = createOwlClient({
  roles: { viewer: { permissions: ["read:reports"] }, admin: { permissions: ["*"] } },
  acl: [{ resource: "report:locked", action: "read", effect: "deny" }]
});
const sessions = { "viewer-token": { userId: "u1", roles: ["viewer"] }, "admin-token": { userId: "u2", roles: ["admin"] } };
const auth = requireAuth({ verifyToken: (token) => sessions[token] || null });
const bearer = (token) => ({ authorization: `Bearer ${token}` });

describe("securityHeaders", () => {
  test("sets the defaults and removes X-Powered-By", async () => {
    const preset = (_req, res, next) => {
      res.setHeader("X-Powered-By", "Express");
      next();
    };
    const { res } = await run([preset, securityHeaders({ "Referrer-Policy": "same-origin" }), ok]);
    expect(res.getHeader("x-powered-by")).toBeUndefined();
    expect(res.getHeader("x-content-type-options")).toBe("nosniff");
    expect(res.getHeader("referrer-policy")).toBe("same-origin");
  });
});

describe("requireAuth + requirePermission", () => {
  const chain = (resource) => [auth, requirePermission("read", resource, owl), ok, errorHandler()];

  test("401 without a token", async () => {
    const { res } = await run(chain("reports"));
    expect(res.statusCode).toBe(401);
    expect(res.getHeader("www-authenticate")).toBe("Bearer");
    expect(res.body.error).toBe("AUTH_REQUIRED");
  });

  test("stores the session and allows a granted permission", async () => {
    const { res } = await run(chain("reports"), { headers: bearer("viewer-token") });
    expect(res.statusCode).toBe(200);
    expect(res.body.session).toEqual({ userId: "u1", roles: ["viewer"], metadata: {} });
  });

  test("403 when no role grants it, including an ACL deny for admin", async () => {
    expect((await run(chain("billing"), { headers: bearer("viewer-token") })).res.statusCode).toBe(403);
    expect((await run(chain("billing"), { headers: bearer("admin-token") })).res.statusCode).toBe(200);
    const locked = await run(chain((req) => `report:${req.params.id}`), { headers: bearer("admin-token"), params: { id: "locked" } });
    expect(locked.res.statusCode).toBe(403);
  });

  test("requirePermission without auth in front responds 401, not 403", async () => {
    const { res } = await run([requirePermission("read", "reports", owl), ok, errorHandler()]);
    expect(res.statusCode).toBe(401);
  });

  test("a misconfigured checker fails at setup, not per request", () => {
    expect(() => requirePermission("read", "reports", {})).toThrow(/rbacManager/);
  });

  test("a verifyToken that throws reaches the error handler as a 500", async () => {
    const broken = requireAuth({
      verifyToken: async () => {
        throw new Error("session store unreachable");
      }
    });
    const { res } = await run([broken, ok, errorHandler()], { headers: bearer("x") });
    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ error: "internal_error" });
  });
});

describe("CSRF", () => {
  test("issueCsrfToken appends to existing Set-Cookie headers", () => {
    const res = createRes();
    res.setHeader("Set-Cookie", "sid=1");
    const token = issueCsrfToken(res);
    expect(res.getHeader("set-cookie")).toEqual(["sid=1", `XSRF-TOKEN=${token}; Path=/; Secure; SameSite=Strict`]);
  });

  test("csrfProtection passes GET and a matching POST, rejects a mismatched POST", async () => {
    const res = createRes();
    const token = issueCsrfToken(res);
    const chain = [csrfProtection(), ok, errorHandler()];

    expect((await run(chain)).res.statusCode).toBe(200);
    const good = await run(chain, { method: "POST", headers: { cookie: `XSRF-TOKEN=${token}`, "x-csrf-token": token } });
    expect(good.res.statusCode).toBe(200);
    const bad = await run(chain, { method: "POST", headers: { cookie: `XSRF-TOKEN=${token}`, "x-csrf-token": "forged" } });
    expect(bad.res.statusCode).toBe(403);
    expect(bad.res.body.error).toBe("CSRF_INVALID");
  });
});

describe("validate + sanitizeBody", () => {
  const schema = { title: { required: true, type: "string", maxLength: 20 } };

  test("400 with field errors", async () => {
    const { res } = await run([validate(schema), ok, errorHandler()], { method: "POST", body: {} });
    expect(res.statusCode).toBe(400);
    expect(res.body.errors).toEqual([{ field: "title", code: "required", message: "title is required" }]);
  });

  test("validates query params and blocks unknown fields on request", async () => {
    const chain = [validate({ q: { type: "string", maxLength: 3 } }, { source: "query", allowUnknownFields: false }), ok, errorHandler()];
    expect((await run(chain, { query: { q: "abc" } })).res.statusCode).toBe(200);
    expect((await run(chain, { query: { q: "abc", admin: "1" } })).res.statusCode).toBe(400);
  });

  test("sanitizes the listed body fields", async () => {
    const { res } = await run([validate({ title: { type: "string", maxLength: 40 } }), sanitizeBody(["title"]), ok, errorHandler()], {
      method: "POST",
      body: { title: "<img src=x onerror=1>hi" }
    });
    expect(res.statusCode).toBe(200);
    expect(res.body.body.title).not.toContain("onerror");
  });
});

describe("guardOutboundUrl", () => {
  const guard = new SSRFGuard({ resolveHost: async (host) => (host === "hooks.example.com" ? ["203.0.113.10"] : ["127.0.0.1"]) });
  const chain = [
    guardOutboundUrl((req) => req.body.webhookUrl, { guard }),
    (req, res) => res.end(JSON.stringify({ host: req.owl.outboundUrl.hostname })),
    errorHandler()
  ];

  test("stores the validated URL", async () => {
    const { res } = await run(chain, { method: "POST", body: { webhookUrl: "https://hooks.example.com/a" } });
    expect(res.body).toEqual({ host: "hooks.example.com" });
  });

  test("403 for an internal target, 400 for a non-URL", async () => {
    expect((await run(chain, { method: "POST", body: { webhookUrl: "https://intranet.example.com" } })).res.statusCode).toBe(403);
    expect((await run(chain, { method: "POST", body: { webhookUrl: 42 } })).res.statusCode).toBe(400);
  });
});

describe("errorHandler", () => {
  test("logs through a redacting SecurityLogger", async () => {
    const entries = [];
    const logger = new SecurityLogger({ sink: (entry) => entries.push(entry) });
    await run([auth, ok, errorHandler({ logger })], { url: "/r?access_token=abc", headers: bearer("nope") });
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ level: "warn", event: "security.auth_required", details: { path: "/r", status: 401 } });
    expect(JSON.stringify(entries)).not.toContain("abc");
  });

  test("hands off to Express when headers were already sent", async () => {
    const failAfterSend = (_req, res, next) => {
      res.headersSent = true;
      next(new Error("late"));
    };
    const { unhandled } = await run([failAfterSend, errorHandler()]);
    expect(unhandled.message).toBe("late");
  });

  test("an error thrown after next() is not blamed on the earlier middleware", async () => {
    const throwingRoute = () => {
      throw new Error("route bug");
    };
    // Simulates Express catching a synchronous throw from the route.
    const guarded = (req, res, next) => {
      try {
        throwingRoute(req, res, next);
      } catch (error) {
        next(error);
      }
    };
    const { res } = await run([auth, guarded, errorHandler()], { headers: bearer("viewer-token") });
    expect(res.statusCode).toBe(500);
  });
});
