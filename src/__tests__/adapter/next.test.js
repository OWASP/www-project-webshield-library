/**
 * @jest-environment node
 */
import { describe, expect, test } from "@jest/globals";
import { readFileSync } from "node:fs";
import { createOwlClient, SecurityError, SecurityErrorCode, SecurityLogger, SSRFGuard } from "@owasp-webshield/core";
import * as react from "@owasp-webshield/react";
import {
  applySecurityHeaders,
  cookieToken,
  ensureCsrfCookie,
  errorResponse,
  guardCsrf,
  issueCsrfToken,
  readJsonBody,
  securityHeadersConfig,
  withOwl
} from "@owasp-webshield/next";
import * as client from "@owasp-webshield/next/client";
import { createServerAuth } from "@owasp-webshield/next/server";
import { setRequestHeaders } from "./stubs/next-headers.js";

const owl = createOwlClient({
  roles: { viewer: { permissions: ["read:reports"] }, admin: { permissions: ["*"] } },
  acl: [{ resource: "report:locked", action: "read", effect: "deny" }]
});
const sessions = { "viewer-token": { userId: "u1", roles: ["viewer"] }, "admin-token": { userId: "u2", roles: ["admin"] } };
const auth = { verifyToken: (token) => sessions[token] || null };
const bearer = (token) => ({ authorization: `Bearer ${token}` });

function request(path = "/api/reports", { method = "GET", headers = {}, json, body } = {}) {
  const init = { method, headers: { ...headers } };
  if (json !== undefined) {
    init.body = JSON.stringify(json);
    init.headers["content-type"] = "application/json";
  } else if (body !== undefined) {
    init.body = body;
  }
  return new Request(`https://app.example.com${path}`, init);
}

// What Next.js passes as the second argument since 15: params is a Promise.
const context = (params = {}) => ({ params: Promise.resolve(params) });
const echo = (_request, _context, state) => Response.json(state);

async function call(handler, req = request(), ctx = context()) {
  const response = await handler(req, ctx);
  const text = await response.text();
  return { response, status: response.status, body: text ? JSON.parse(text) : undefined };
}

describe("withOwl: auth + permission", () => {
  const route = (resource) => withOwl(echo, { auth, permission: { action: "read", resource, checker: owl } });

  test("401 without a token, with the Bearer challenge and security headers", async () => {
    const { response, status, body } = await call(route("reports"));
    expect(status).toBe(401);
    expect(body.error).toBe("AUTH_REQUIRED");
    expect(response.headers.get("www-authenticate")).toBe("Bearer");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });

  test("passes the session and resolved params to the handler", async () => {
    const { status, body } = await call(route("reports"), request("/api/reports", { headers: bearer("viewer-token") }), context({ id: "7" }));
    expect(status).toBe(200);
    expect(body).toEqual({ params: { id: "7" }, session: { userId: "u1", roles: ["viewer"], metadata: {} } });
  });

  test("403 when no role grants it; a resource function sees the params", async () => {
    expect((await call(route("billing"), request("/", { headers: bearer("viewer-token") }))).status).toBe(403);
    expect((await call(route("billing"), request("/", { headers: bearer("admin-token") }))).status).toBe(200);
    const scoped = route(async ({ params }) => `report:${params.id}`);
    expect((await call(scoped, request("/", { headers: bearer("admin-token") }), context({ id: "locked" }))).status).toBe(403);
  });

  test("accepts Next.js 14's plain-object params", async () => {
    const { body } = await call(withOwl(echo), request(), { params: { slug: "a" } });
    expect(body).toEqual({ params: { slug: "a" } });
  });

  test("permission without auth responds 401, not 403", async () => {
    const { status } = await call(withOwl(echo, { permission: { action: "read", resource: "reports", checker: owl } }));
    expect(status).toBe(401);
  });

  test("a misconfigured checker fails when the route is defined", () => {
    expect(() => withOwl(echo, { permission: { action: "read", resource: "x", checker: {} } })).toThrow(/rbacManager/);
  });

  test("reads the token from a cookie with cookieToken()", async () => {
    const handler = withOwl(echo, { auth: { ...auth, getToken: cookieToken("sid") } });
    expect((await call(handler, request("/", { headers: { cookie: "sid=viewer-token" } }))).status).toBe(200);
    // Two copies of the session cookie is what cookie tossing looks like.
    expect((await call(handler, request("/", { headers: { cookie: "sid=viewer-token; sid=admin-token" } }))).status).toBe(401);
  });
});

describe("withOwl: CSRF", () => {
  const handler = withOwl(echo, { csrf: true });

  test("passes GET and a matching POST, rejects a mismatched POST", async () => {
    const token = issueCsrfToken(new Response());
    const cookie = `XSRF-TOKEN=${token}`;
    expect((await call(handler)).status).toBe(200);
    expect((await call(handler, request("/", { method: "POST", headers: { cookie, "x-csrf-token": token } }))).status).toBe(200);
    const bad = await call(handler, request("/", { method: "POST", headers: { cookie, "x-csrf-token": "forged" } }));
    expect(bad.status).toBe(403);
    expect(bad.body.error).toBe("CSRF_INVALID");
  });

  test("takes verifyCsrf options, such as a session-stored token", async () => {
    const synchronizer = withOwl(echo, { csrf: { getExpectedToken: () => "server-token" } });
    const req = request("/", { method: "DELETE", headers: { "x-csrf-token": "server-token" } });
    expect((await call(synchronizer, req)).status).toBe(200);
  });
});

describe("withOwl: query and body", () => {
  const schema = { title: { required: true, type: "string", maxLength: 20 } };

  test("validates the query string and rejects unknown params on request", async () => {
    const handler = withOwl(echo, { query: { schema: { q: { type: "string", maxLength: 3 } }, allowUnknownFields: false } });
    expect((await call(handler, request("/?q=abc"))).body.query).toEqual({ q: "abc" });
    expect((await call(handler, request("/?q=abcd"))).status).toBe(400);
    expect((await call(handler, request("/?q=a&admin=1"))).status).toBe(400);
  });

  test("400 with per-field errors, and mass assignment blocked", async () => {
    const handler = withOwl(echo, { body: { schema, allowUnknownFields: false } });
    const missing = await call(handler, request("/", { method: "POST", json: {} }));
    expect(missing.status).toBe(400);
    expect(missing.body.errors).toEqual([{ field: "title", code: "required", message: "title is required" }]);
    expect((await call(handler, request("/", { method: "POST", json: { title: "a", role: "admin" } }))).status).toBe(400);
  });

  test("sanitizes the listed fields", async () => {
    const handler = withOwl(echo, { body: { schema: { title: { type: "string" } }, sanitize: ["title"] } });
    const { body } = await call(handler, request("/", { method: "POST", json: { title: "<img src=x onerror=1>hi" } }));
    expect(body.body.title).not.toContain("onerror");
  });

  test("415 for a non-JSON body, 400 for malformed JSON, 413 over the limit", async () => {
    const handler = withOwl(echo, { body: { limit: 32 } });
    expect((await call(handler, request("/", { method: "POST", body: "title=x" }))).status).toBe(415);
    const malformed = request("/", { method: "POST", body: "{", headers: { "content-type": "application/json" } });
    expect(await call(handler, malformed)).toMatchObject({ status: 400, body: { error: "bad_request", message: "Malformed JSON request body" } });
    expect((await call(handler, request("/", { method: "POST", json: { title: "x".repeat(40) } }))).status).toBe(413);
  });
});

describe("readJsonBody", () => {
  test("an empty or missing body is undefined", async () => {
    expect(await readJsonBody(request())).toBeUndefined();
    expect(await readJsonBody(request("/", { method: "POST", body: "" }))).toBeUndefined();
  });

  test("accepts +json types and rejects a declared length over the limit without reading", async () => {
    const patch = request("/", { method: "PATCH", body: '{"a":1}', headers: { "content-type": "application/merge-patch+json" } });
    expect(await readJsonBody(patch)).toEqual({ a: 1 });
    const big = request("/", { method: "POST", body: "{}", headers: { "content-type": "application/json", "content-length": "999" } });
    await expect(readJsonBody(big, { limit: 10 })).rejects.toMatchObject({ status: 413 });
  });

  test("stops reading a stream once it passes the limit", async () => {
    let pulled = 0;
    const stream = new ReadableStream({
      pull(controller) {
        pulled += 1;
        controller.enqueue(new TextEncoder().encode("x".repeat(16)));
      }
    });
    const req = new Request("https://app.example.com/", { method: "POST", body: stream, duplex: "half", headers: { "content-type": "application/json" } });
    await expect(readJsonBody(req, { limit: 40 })).rejects.toMatchObject({ status: 413 });
    expect(pulled).toBeLessThan(5);
  });
});

describe("withOwl: outboundUrl", () => {
  const guard = new SSRFGuard({ resolveHost: async (host) => (host === "hooks.example.com" ? ["203.0.113.10"] : ["127.0.0.1"]) });
  const handler = withOwl((_req, _ctx, { outboundUrl }) => Response.json({ host: outboundUrl.hostname }), {
    body: {},
    outboundUrl: { getUrl: ({ body }) => body?.webhookUrl, guard }
  });

  test("passes the checked URL to the handler", async () => {
    const { body } = await call(handler, request("/", { method: "POST", json: { webhookUrl: "https://hooks.example.com/a" } }));
    expect(body).toEqual({ host: "hooks.example.com" });
  });

  test("403 for an internal target, 400 for a non-URL", async () => {
    expect((await call(handler, request("/", { method: "POST", json: { webhookUrl: "https://intranet.example.com" } }))).status).toBe(403);
    expect((await call(handler, request("/", { method: "POST", json: { webhookUrl: 42 } }))).status).toBe(400);
  });
});

describe("withOwl: responses and errors", () => {
  test("keeps headers the handler set, and can skip or override the defaults", async () => {
    const own = withOwl(() => new Response("ok", { headers: { "Referrer-Policy": "same-origin" } }));
    const response = await own(request(), context());
    expect(response.headers.get("referrer-policy")).toBe("same-origin");
    expect(response.headers.get("x-frame-options")).toBe("DENY");

    const none = await withOwl(() => new Response("ok"), { securityHeaders: false })(request(), context());
    expect(none.headers.get("x-frame-options")).toBeNull();
    const dropped = await withOwl(() => new Response("ok"), { securityHeaders: { "X-Frame-Options": false } })(request(), context());
    expect(dropped.headers.get("x-frame-options")).toBeNull();
  });

  test("adds headers to a response with immutable headers", async () => {
    const response = await withOwl(() => Response.redirect("https://app.example.com/login", 307))(request(), context());
    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe("https://app.example.com/login");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });

  test("maps SecurityErrors thrown by the handler, and hides 500 messages", async () => {
    const deny = () => {
      throw new SecurityError(SecurityErrorCode.ACCESS_DENIED, "nope");
    };
    expect(await call(withOwl(deny))).toMatchObject({ status: 403, body: { error: "ACCESS_DENIED", message: "nope" } });
    const broken = withOwl(() => {
      throw new Error("db password is hunter2");
    });
    expect(await call(broken)).toMatchObject({ status: 500, body: { error: "internal_error" } });
    const quiet = withOwl(deny, { exposeMessages: false });
    expect((await call(quiet)).body).toEqual({ error: "ACCESS_DENIED" });
  });

  test("rethrows Next.js redirect(), notFound() and bailout errors", async () => {
    const thrower = (digest) => withOwl(() => {
      throw Object.assign(new Error(digest), { digest });
    });
    for (const digest of ["NEXT_REDIRECT;replace;/login;307;", "NEXT_HTTP_ERROR_FALLBACK;404", "DYNAMIC_SERVER_USAGE", "BAILOUT_TO_CLIENT_SIDE_RENDERING"]) {
      await expect(thrower(digest)(request(), context())).rejects.toMatchObject({ digest });
    }
    const wrapped = withOwl(() => {
      throw new Error("wrapped", { cause: { digest: "NEXT_REDIRECT;push;/x;303;" } });
    });
    await expect(wrapped(request(), context())).rejects.toThrow("wrapped");
    // A lookalike digest is an ordinary error.
    expect((await call(thrower("NEXT_REDIRECTED_ELSEWHERE"))).status).toBe(500);
  });

  test("returns a non-Response result untouched for Next.js to report", async () => {
    expect(await withOwl(() => undefined)(request(), context())).toBeUndefined();
  });

  test("logs failures through a redacting SecurityLogger without the query string", async () => {
    const entries = [];
    const logger = new SecurityLogger({ sink: (entry) => entries.push(entry) });
    await withOwl(echo, { auth, logger })(request("/api/r?access_token=abc", { headers: bearer("nope") }), context());
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ level: "warn", event: "security.auth_required", details: { path: "/api/r", status: 401 } });
    expect(JSON.stringify(entries)).not.toContain("abc");
  });
});

describe("CSRF cookies", () => {
  test("issueCsrfToken appends to a plain Response's Set-Cookie", () => {
    const response = new Response(null, { headers: { "Set-Cookie": "sid=1" } });
    const token = issueCsrfToken(response);
    expect(response.headers.getSetCookie()).toEqual(["sid=1", `XSRF-TOKEN=${token}; Path=/; Secure; SameSite=Strict`]);
  });

  test("issueCsrfToken goes through NextResponse.cookies when there is one", () => {
    const set = [];
    const response = Object.assign(new Response(), { cookies: { set: (...args) => set.push(args) } });
    const token = issueCsrfToken(response, { cookieName: "__Host-csrf", cookie: { maxAge: 3600.5 } });
    expect(set).toEqual([["__Host-csrf", token, { path: "/", secure: true, httpOnly: false, sameSite: "strict", maxAge: 3600 }]]);
    expect(response.headers.get("set-cookie")).toBeNull();
  });

  test("issueCsrfToken rejects an invalid cookie configuration", () => {
    expect(() => issueCsrfToken(new Response(), { cookie: { sameSite: "None", secure: false } })).toThrow(SecurityError);
  });

  test("ensureCsrfCookie reuses the request's token and issues one otherwise", () => {
    const reused = new Response();
    expect(ensureCsrfCookie(request("/", { headers: { cookie: "XSRF-TOKEN=abc" } }), reused)).toBe("abc");
    expect(reused.headers.get("set-cookie")).toBeNull();

    for (const cookie of [undefined, "XSRF-TOKEN=a; XSRF-TOKEN=b"]) {
      const issued = new Response();
      const token = ensureCsrfCookie(request("/", { headers: cookie ? { cookie } : {} }), issued);
      expect(issued.headers.get("set-cookie")).toContain(`XSRF-TOKEN=${token}`);
    }
  });
});

describe("guardCsrf", () => {
  test("null for a safe or valid request, a 403 response otherwise", async () => {
    expect(await guardCsrf(request())).toBeNull();
    const valid = request("/", { method: "POST", headers: { cookie: "XSRF-TOKEN=t0k3n", "x-csrf-token": "t0k3n" } });
    expect(await guardCsrf(valid)).toBeNull();
    const rejected = await guardCsrf(request("/", { method: "POST" }));
    expect(rejected.status).toBe(403);
    expect(await rejected.json()).toMatchObject({ error: "CSRF_INVALID" });
    expect(rejected.headers.get("x-frame-options")).toBe("DENY");
  });

  test("passes a custom cookie name through", async () => {
    const req = request("/", { method: "POST", headers: { cookie: "csrf=t0k3n", "x-csrf-token": "t0k3n" } });
    expect(await guardCsrf(req, { cookieName: "csrf" })).toBeNull();
  });
});

describe("security headers", () => {
  test("securityHeadersConfig returns next.config headers with a page-friendly CSP", () => {
    const [entry] = securityHeadersConfig({}, { dev: false });
    expect(entry.source).toBe("/(.*)");
    const csp = entry.headers.find(({ key }) => key === "Content-Security-Policy").value;
    expect(csp).toContain("script-src 'self' 'unsafe-inline'");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(entry.headers).toContainEqual({ key: "X-Content-Type-Options", value: "nosniff" });
  });

  test("securityHeadersConfig allows eval in dev and takes overrides in any case", () => {
    const [dev] = securityHeadersConfig({}, { dev: true, source: "/app/:path*" });
    expect(dev.source).toBe("/app/:path*");
    expect(dev.headers.find(({ key }) => key === "Content-Security-Policy").value).toContain("'unsafe-eval'");

    const [custom] = securityHeadersConfig({ "content-security-policy": "default-src 'self'", "X-Frame-Options": false });
    expect(custom.headers.filter(({ key }) => /content-security-policy/i.test(key))).toEqual([
      { key: "content-security-policy", value: "default-src 'self'" }
    ]);
    expect(custom.headers.some(({ key }) => key === "X-Frame-Options")).toBe(false);
  });

  test("applySecurityHeaders rethrows errors other than immutable headers", () => {
    const response = { headers: { has: () => false, set: () => { throw new RangeError("boom"); } } };
    expect(() => applySecurityHeaders(response)).toThrow(RangeError);
  });

  test("errorResponse can skip the security headers", async () => {
    const response = errorResponse(new SecurityError(SecurityErrorCode.INVALID_INPUT, "bad"), { securityHeaders: false });
    expect(response.status).toBe(400);
    expect(response.headers.get("x-frame-options")).toBeNull();
  });
});

describe("@owasp-webshield/next/server", () => {
  const { getSession, requireSession, requirePermission } = createServerAuth({ ...auth, getToken: cookieToken("sid"), checker: owl });

  test("getSession reads the current request's cookie, or returns null", async () => {
    setRequestHeaders({ cookie: "sid=viewer-token" });
    expect(await getSession()).toEqual({ userId: "u1", roles: ["viewer"], metadata: {} });
    setRequestHeaders({ cookie: "sid=expired" });
    expect(await getSession()).toBeNull();
    await expect(requireSession()).rejects.toMatchObject({ code: "AUTH_REQUIRED" });
  });

  test("getSession lets a broken session store propagate", async () => {
    const broken = createServerAuth({
      verifyToken: async () => {
        throw new Error("store down");
      }
    });
    setRequestHeaders(bearer("x"));
    await expect(broken.getSession()).rejects.toThrow("store down");
  });

  test("requirePermission returns the session or throws ACCESS_DENIED", async () => {
    setRequestHeaders({ cookie: "sid=viewer-token" });
    expect((await requirePermission("read", "reports")).userId).toBe("u1");
    await expect(requirePermission("write", "reports")).rejects.toMatchObject({ code: "ACCESS_DENIED" });
  });

  test("requirePermission without a checker is a misconfiguration", async () => {
    setRequestHeaders(bearer("viewer-token"));
    await expect(createServerAuth(auth).requirePermission("read", "reports")).rejects.toMatchObject({ code: "MISCONFIGURATION" });
  });
});

describe("@owasp-webshield/next/client", () => {
  test("is a client module", () => {
    const source = readFileSync(new URL("../../adapters/next/client.js", import.meta.url), "utf8");
    expect(source.startsWith('"use client";')).toBe(true);
  });

  test("re-exports every named React adapter export except the category namespaces", () => {
    const named = Object.keys(react).filter((name) => !/^A\d\d/.test(name));
    expect(Object.keys(client).sort()).toEqual(named.sort());
    for (const name of named) expect(client[name]).toBe(react[name]);
  });
});
