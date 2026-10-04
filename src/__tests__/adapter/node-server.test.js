/**
 * @jest-environment node
 */
import { describe, expect, jest, test } from "@jest/globals";
import { createOwlClient, SecurityConfigManager, SecurityError, SecurityErrorCode, SSRFGuard } from "@owasp-webshield/core";
import {
  assertHardened,
  assertPermission,
  assertSafeOutboundUrl,
  assertValidInput,
  authenticate,
  checkPermission,
  extractBearerToken,
  getCookieValues,
  getHeader,
  issueCsrfToken,
  logRequestError,
  requestLogContext,
  sanitizeFields,
  securityHeaders,
  serializeCookie,
  statusForSecurityError,
  toErrorResponse,
  toPermissionChecker,
  verifyCsrf
} from "@owasp-webshield/node";

function request({ method = "GET", url = "/", headers = {}, ...rest } = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return { method, url, headers: lower, ...rest };
}

async function codeOf(promiseOrFn) {
  try {
    await (typeof promiseOrFn === "function" ? promiseOrFn() : promiseOrFn);
  } catch (error) {
    return error instanceof SecurityError ? error.code : `non-security: ${error}`;
  }
  return "no error";
}

describe("request accessors", () => {
  test("getHeader reads Node header objects and Fetch Headers", () => {
    expect(getHeader(request({ headers: { "X-Test": "a" } }), "x-test")).toBe("a");
    expect(getHeader({ headers: { "set-cookie": ["a", "b"] } }, "Set-Cookie")).toBe("a");
    expect(getHeader({ headers: new Headers({ "X-Test": "b" }) }, "x-test")).toBe("b");
    expect(getHeader({ headers: new Headers() }, "x-test")).toBeUndefined();
    expect(getHeader({}, "x-test")).toBeUndefined();
  });

  test("requestLogContext drops the query string and keeps only safe fields", () => {
    const context = requestLogContext(
      request({
        method: "post",
        url: "/reset?token=secret",
        headers: { authorization: "Bearer abc", "x-request-id": "r-1" },
        ip: "203.0.113.5"
      })
    );
    expect(context).toEqual({ method: "POST", path: "/reset", ip: "203.0.113.5", requestId: "r-1" });
  });
});

describe("A07 authenticate", () => {
  const verifyToken = async (token) => (token === "good" ? { userId: 7, roles: ["admin"] } : null);

  test("extractBearerToken accepts only a well-formed bearer header", () => {
    expect(extractBearerToken(request({ headers: { authorization: "Bearer abc.def-_~+/=" } }))).toBe("abc.def-_~+/=");
    expect(extractBearerToken(request({ headers: { authorization: "bearer abc" } }))).toBe("abc");
    expect(extractBearerToken(request({ headers: { authorization: "Basic abc" } }))).toBeNull();
    expect(extractBearerToken(request({ headers: { authorization: "Bearer a b" } }))).toBeNull();
    expect(extractBearerToken(request())).toBeNull();
  });

  test("returns a normalized per-request session", async () => {
    const session = await authenticate(request({ headers: { authorization: "Bearer good" } }), { verifyToken });
    expect(session).toEqual({ userId: "7", roles: ["admin"], metadata: {} });
  });

  test("rejects missing and unknown tokens with AUTH_REQUIRED", async () => {
    expect(await codeOf(authenticate(request(), { verifyToken }))).toBe(SecurityErrorCode.AUTH_REQUIRED);
    expect(await codeOf(authenticate(request({ headers: { authorization: "Bearer bad" } }), { verifyToken }))).toBe(
      SecurityErrorCode.AUTH_REQUIRED
    );
  });

  test("requires a verifyToken function", async () => {
    expect(await codeOf(authenticate(request(), {}))).toBe(SecurityErrorCode.MISCONFIGURATION);
  });

  test("concurrent requests don't share sessions", async () => {
    const lookup = { a: { userId: "alice", roles: ["viewer"] }, b: { userId: "bob", roles: ["admin"] } };
    const slowVerify = (token) => new Promise((resolve) => setTimeout(() => resolve(lookup[token]), token === "a" ? 10 : 0));
    const [alice, bob] = await Promise.all([
      authenticate(request({ headers: { authorization: "Bearer a" } }), { verifyToken: slowVerify }),
      authenticate(request({ headers: { authorization: "Bearer b" } }), { verifyToken: slowVerify })
    ]);
    expect(alice.userId).toBe("alice");
    expect(bob.userId).toBe("bob");
  });
});

describe("A01 access control", () => {
  const owl = createOwlClient({
    roles: { viewer: { permissions: ["read:reports"] }, editor: { permissions: ["write:reports"] } },
    acl: [{ resource: "reports", action: "delete", effect: "deny" }]
  });

  test("allows when any role of the session grants it", () => {
    const session = { roles: ["viewer", "editor"] };
    expect(checkPermission({ session, action: "write", resource: "reports" }, owl).allowed).toBe(true);
    expect(checkPermission({ session, action: "delete", resource: "reports" }, owl)).toEqual({
      allowed: false,
      reason: "acl_deny_override"
    });
    expect(checkPermission({ session: { roles: [] }, action: "read", resource: "reports" }, owl).reason).toBe("no_role");
  });

  test("assertPermission throws AUTH_REQUIRED without a session and ACCESS_DENIED otherwise", async () => {
    expect(await codeOf(() => assertPermission({ session: null, action: "read", resource: "reports" }, owl))).toBe(
      SecurityErrorCode.AUTH_REQUIRED
    );
    expect(await codeOf(() => assertPermission({ session: { roles: ["viewer"] }, action: "write", resource: "reports" }, owl))).toBe(
      SecurityErrorCode.ACCESS_DENIED
    );
  });

  test("toPermissionChecker rejects an unusable source", async () => {
    expect(await codeOf(() => toPermissionChecker({}))).toBe(SecurityErrorCode.MISCONFIGURATION);
    expect(toPermissionChecker({ rbacManager: owl.rbacManager }).check({ role: "viewer", action: "read", resource: "reports" }).allowed).toBe(true);
  });
});

describe("A03 validation and sanitization", () => {
  const schema = { title: { required: true, type: "string", maxLength: 10 } };

  test("returns valid input and throws INVALID_INPUT with field errors", () => {
    expect(assertValidInput({ title: "ok" }, schema)).toEqual({ title: "ok" });
    let error;
    try {
      assertValidInput({ title: "far too long here" }, schema);
    } catch (caught) {
      error = caught;
    }
    expect(error.code).toBe(SecurityErrorCode.INVALID_INPUT);
    expect(error.details.errors[0]).toMatchObject({ field: "title", code: "maxLength" });
  });

  test("validates a non-object body as empty", async () => {
    expect(await codeOf(() => assertValidInput(["title"], schema))).toBe(SecurityErrorCode.INVALID_INPUT);
    expect(await codeOf(() => assertValidInput("title", schema))).toBe(SecurityErrorCode.INVALID_INPUT);
  });

  test("allowUnknownFields: false blocks mass assignment", () => {
    expect(() => assertValidInput({ title: "ok", role: "admin" }, schema, { allowUnknownFields: false })).toThrow(SecurityError);
    expect(assertValidInput({ title: "ok", role: "admin" }, schema)).toEqual({ title: "ok", role: "admin" });
  });

  test("sanitizeFields sanitizes only the listed string fields", () => {
    const input = { bio: "<b>hi</b><script>x()</script>", raw: "<i>keep</i>", count: 3 };
    const output = sanitizeFields(input, ["bio", "count"]);
    expect(output.bio).not.toContain("<script>");
    expect(output.raw).toBe("<i>keep</i>");
    expect(output.count).toBe(3);
    expect(input.bio).toContain("<script>");
    expect(sanitizeFields(null, ["bio"])).toBeNull();
  });
});

describe("A05 headers and startup hardening", () => {
  test("securityHeaders merges overrides case-insensitively and drops false", () => {
    const headers = securityHeaders({ "content-security-policy": "default-src 'self'", "X-Frame-Options": false });
    expect(headers["content-security-policy"]).toBe("default-src 'self'");
    expect(headers["Content-Security-Policy"]).toBeUndefined();
    expect(headers["X-Frame-Options"]).toBeUndefined();
    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
  });

  test("assertHardened throws for high findings and reports lower ones", () => {
    const logger = { warn: jest.fn() };
    expect(() => assertHardened({ debug: true, cors: { origin: "*" } }, { logger })).toThrow(/debug_enabled, wildcard_cors/);
    expect(logger.warn).toHaveBeenCalledWith("config.unsafe", expect.objectContaining({ id: "debug_enabled" }));

    const report = assertHardened(new SecurityConfigManager({ cookies: { sameSite: "None" } }));
    expect(report.map((f) => f.id)).toEqual(["samesite_none"]);
    expect(() => assertHardened({ cookies: { sameSite: "None" } }, { failOn: "medium" })).toThrow(SecurityError);
    expect(assertHardened({ debug: true }, { failOn: false })).toHaveLength(1);
  });

  test("assertHardened rejects an unknown threshold", () => {
    expect(() => assertHardened({}, { failOn: "critical" })).toThrow(/failOn/);
  });
});

describe("cookies", () => {
  test("getCookieValues returns every occurrence", () => {
    const req = request({ headers: { cookie: "a=1; XSRF-TOKEN=x%20y; XSRF-TOKEN=z; bad=%E0" } });
    expect(getCookieValues(req, "XSRF-TOKEN")).toEqual(["x y", "z"]);
    expect(getCookieValues(req, "bad")).toEqual([""]);
    expect(getCookieValues(request(), "a")).toEqual([]);
  });

  test("serializeCookie defaults to Secure, HttpOnly, SameSite=Strict", () => {
    expect(serializeCookie("sid", "a b")).toBe("sid=a%20b; Path=/; Secure; HttpOnly; SameSite=Strict");
    expect(serializeCookie("sid", "v", { maxAge: 60.9, httpOnly: false, sameSite: "Lax", domain: "example.com" })).toBe(
      "sid=v; Path=/; Domain=example.com; Max-Age=60; Secure; SameSite=Lax"
    );
  });

  test("serializeCookie rejects unsafe combinations", () => {
    expect(() => serializeCookie("bad name", "v")).toThrow(SecurityError);
    expect(() => serializeCookie("a", "v", { sameSite: "loose" })).toThrow(SecurityError);
    expect(() => serializeCookie("a", "v", { sameSite: "None", secure: false })).toThrow(/Secure/);
    expect(() => serializeCookie("__Host-a", "v", { domain: "example.com" })).toThrow(/__Host-/);
  });
});

describe("A08 CSRF", () => {
  test("issueCsrfToken returns a token and a script-readable cookie", () => {
    const { token, setCookie } = issueCsrfToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(setCookie).toBe(`XSRF-TOKEN=${token}; Path=/; Secure; SameSite=Strict`);
  });

  test("safe methods skip the check", async () => {
    await expect(verifyCsrf(request({ method: "GET" }))).resolves.toBe(false);
    await expect(verifyCsrf(request({ method: "options" }))).resolves.toBe(false);
  });

  test("double-submit: header must match the single cookie", async () => {
    const { token } = issueCsrfToken();
    const post = (headers) => request({ method: "POST", headers });
    await expect(verifyCsrf(post({ cookie: `XSRF-TOKEN=${token}`, "x-csrf-token": token }))).resolves.toBe(true);
    expect(await codeOf(verifyCsrf(post({ cookie: `XSRF-TOKEN=${token}`, "x-csrf-token": "wrong" })))).toBe(SecurityErrorCode.CSRF_INVALID);
    expect(await codeOf(verifyCsrf(post({ "x-csrf-token": token })))).toBe(SecurityErrorCode.CSRF_INVALID);
    expect(await codeOf(verifyCsrf(post({ cookie: `XSRF-TOKEN=${token}` })))).toBe(SecurityErrorCode.CSRF_INVALID);
    expect(await codeOf(verifyCsrf(post({ cookie: "XSRF-TOKEN=", "x-csrf-token": "" })))).toBe(SecurityErrorCode.CSRF_INVALID);
  });

  test("double-submit: a tossed duplicate cookie is rejected even if one matches", async () => {
    const req = request({ method: "POST", headers: { cookie: "XSRF-TOKEN=attacker; XSRF-TOKEN=attacker", "x-csrf-token": "attacker" } });
    expect(await codeOf(verifyCsrf(req))).toBe(SecurityErrorCode.CSRF_INVALID);
  });

  test("synchronizer: compares against the session-stored token", async () => {
    const sessions = { s1: "tok-1" };
    const options = { getExpectedToken: async (req) => sessions[req.sessionId] };
    await expect(verifyCsrf(request({ method: "DELETE", sessionId: "s1", headers: { "x-csrf-token": "tok-1" } }), options)).resolves.toBe(true);
    expect(await codeOf(verifyCsrf(request({ method: "DELETE", sessionId: "s2", headers: { "x-csrf-token": "tok-1" } }), options))).toBe(
      SecurityErrorCode.CSRF_INVALID
    );
  });
});

describe("A10 outbound URL", () => {
  const guard = new SSRFGuard({ resolveHost: async (host) => (host === "hooks.example.com" ? ["203.0.113.10"] : ["10.0.0.5"]) });

  test("uses a default SSRFGuard when none is passed", async () => {
    expect(await codeOf(assertSafeOutboundUrl("http://127.0.0.1:8080/admin"))).toBe(SecurityErrorCode.SSRF_BLOCKED);
    expect(await codeOf(assertSafeOutboundUrl("file:///etc/passwd"))).toBe(SecurityErrorCode.SSRF_BLOCKED);
  });

  test("allows a public target and blocks private ones", async () => {
    const url = await assertSafeOutboundUrl("https://hooks.example.com/x", { guard });
    expect(url.hostname).toBe("hooks.example.com");
    expect(await codeOf(assertSafeOutboundUrl("https://internal.example.com/", { guard }))).toBe(SecurityErrorCode.SSRF_BLOCKED);
    expect(await codeOf(assertSafeOutboundUrl("http://169.254.169.254/latest/meta-data", { guard }))).toBe(SecurityErrorCode.SSRF_BLOCKED);
  });

  test("rejects non-URLs as INVALID_INPUT", async () => {
    expect(await codeOf(assertSafeOutboundUrl("not a url", { guard }))).toBe(SecurityErrorCode.INVALID_INPUT);
    expect(await codeOf(assertSafeOutboundUrl(undefined, { guard }))).toBe(SecurityErrorCode.INVALID_INPUT);
  });
});

describe("error mapping", () => {
  test("maps each SecurityErrorCode to a status", () => {
    expect(statusForSecurityError(SecurityErrorCode.INVALID_INPUT)).toBe(400);
    expect(statusForSecurityError(SecurityErrorCode.TOKEN_EXPIRED)).toBe(401);
    expect(statusForSecurityError(SecurityErrorCode.CSRF_INVALID)).toBe(403);
    expect(statusForSecurityError(SecurityErrorCode.CRYPTO_ERROR)).toBe(500);
    expect(statusForSecurityError("SOMETHING_NEW")).toBe(500);
  });

  test("client errors carry code and message; 401s name the Bearer scheme", () => {
    expect(toErrorResponse(new SecurityError(SecurityErrorCode.AUTH_REQUIRED, "Missing bearer token"))).toEqual({
      status: 401,
      headers: { "WWW-Authenticate": "Bearer" },
      body: { error: "AUTH_REQUIRED", message: "Missing bearer token" }
    });
    expect(toErrorResponse(new SecurityError(SecurityErrorCode.TOKEN_EXPIRED, "x")).headers["WWW-Authenticate"]).toContain("invalid_token");
    expect(toErrorResponse(new SecurityError(SecurityErrorCode.ACCESS_DENIED, "no"), { exposeMessages: false }).body).toEqual({
      error: "ACCESS_DENIED"
    });
  });

  test("validation errors list fields but never the submitted values", () => {
    const error = new SecurityError(SecurityErrorCode.INVALID_INPUT, "bad", {
      errors: [{ field: "pw", code: "minLength", message: "pw must be at least 8", value: "hunter2" }]
    });
    expect(toErrorResponse(error).body.errors).toEqual([{ field: "pw", code: "minLength", message: "pw must be at least 8" }]);
  });

  test("server-side failures never expose their message", () => {
    expect(toErrorResponse(new SecurityError(SecurityErrorCode.MISCONFIGURATION, "secret path /etc/x")).body).toEqual({ error: "internal_error" });
    expect(toErrorResponse(new Error("db password wrong"))).toEqual({ status: 500, headers: {}, body: { error: "internal_error" } });
    expect(toErrorResponse("boom").status).toBe(500);
  });

  test("http-errors style client errors keep their status", () => {
    const parseError = Object.assign(new Error("Unexpected token"), { status: 400, expose: true });
    expect(toErrorResponse(parseError)).toEqual({ status: 400, headers: {}, body: { error: "bad_request", message: "Unexpected token" } });
    const hidden = Object.assign(new Error("internal detail"), { statusCode: 413 });
    expect(toErrorResponse(hidden).body).toEqual({ error: "bad_request" });
  });
});

describe("A09 logRequestError", () => {
  test("logs security rejections at warn and failures at error", () => {
    const logger = { warn: jest.fn(), error: jest.fn() };
    const req = request({ method: "POST", url: "/x?token=1" });
    logRequestError(logger, new SecurityError(SecurityErrorCode.CSRF_INVALID, "bad"), req);
    expect(logger.warn).toHaveBeenCalledWith("security.csrf_invalid", expect.objectContaining({ status: 403, path: "/x" }));

    logRequestError(logger, Object.assign(new Error("parse"), { status: 400 }), req);
    expect(logger.warn).toHaveBeenCalledWith("request.rejected", expect.objectContaining({ status: 400 }));

    logRequestError(logger, new Error("db down"), req);
    expect(logger.error).toHaveBeenCalledWith("request.failed", expect.objectContaining({ status: 500, message: "db down" }));

    logRequestError(logger, new SecurityError(SecurityErrorCode.CRYPTO_ERROR, "x"));
    expect(logger.error).toHaveBeenCalledWith("security.crypto_error", expect.objectContaining({ status: 500 }));

    expect(() => logRequestError(undefined, new Error("x"), req)).not.toThrow();
  });
});
