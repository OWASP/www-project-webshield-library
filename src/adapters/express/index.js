import {
  assertPermission,
  assertSafeOutboundUrl,
  assertValidInput,
  authenticate,
  issueCsrfToken as issueCsrfCookie,
  logRequestError,
  sanitizeFields,
  securityHeaders as buildSecurityHeaders,
  toErrorResponse,
  toPermissionChecker,
  verifyCsrf
} from "@owasp-webshield/node";
import { middleware, owlState } from "./middleware.js";

// Startup and helpers that aren't middleware, re-exported so an Express app
// only needs this one import.
export {
  assertHardened,
  DEFAULT_SECURITY_HEADERS,
  generateCsrfToken,
  statusForSecurityError,
  toErrorResponse
} from "@owasp-webshield/node";

// --- A05 Security Misconfiguration -------------------------------------------

/**
 * Sets the security response headers (see `DEFAULT_SECURITY_HEADERS`) and removes
 * `X-Powered-By`. Register it first, so error responses get the headers too.
 * @param {Record<string, string|false|null>} [overrides] `false` drops a header
 */
export function securityHeaders(overrides) {
  const headers = buildSecurityHeaders(overrides);
  return function owlSecurityHeaders(_req, res, next) {
    res.removeHeader("X-Powered-By");
    for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
    next();
  };
}

// --- A07 Authentication & Session --------------------------------------------

/**
 * Authenticates the request with `verifyToken` and stores the session on
 * `req.owl.session`; responds 401 through `errorHandler()` otherwise.
 * @param {Parameters<typeof authenticate>[1]} options
 */
export function requireAuth(options) {
  return middleware(async (req) => {
    owlState(req).session = await authenticate(req, options);
  });
}

// --- A01 Access Control -------------------------------------------------------

/**
 * Allows the request only if a role of `req.owl.session` has `action` on
 * `resource` (RBAC, with ACL deny-overrides). Mount after `requireAuth()`.
 *
 * @param {string} action
 * @param {string | ((req: any) => string)} resource a function can scope it
 *   to the request, e.g. `(req) => \`report:${req.params.id}\``
 * @param {object} checkerSource a `PermissionChecker`, or the object returned by
 *   `createOwlClient()` (anything with an `rbacManager`, optionally an `aclManager`)
 */
export function requirePermission(action, resource, checkerSource) {
  const checker = toPermissionChecker(checkerSource);
  return middleware((req) => {
    const target = typeof resource === "function" ? resource(req) : resource;
    assertPermission({ session: req.owl?.session, action, resource: target }, checker);
  });
}

// --- A08 Data Integrity (CSRF) -----------------------------------------------

/**
 * Rejects POST/PUT/PATCH/DELETE requests without a valid `X-CSRF-Token`
 * header. By default the expected token is the double-submit `XSRF-TOKEN`
 * cookie set by `issueCsrfToken()`; pass `getExpectedToken` to check a token
 * stored in the server-side session instead.
 * @param {Parameters<typeof verifyCsrf>[1]} [options]
 */
export function csrfProtection(options) {
  return middleware((req) => verifyCsrf(req, options));
}

/**
 * Sets a fresh CSRF cookie on the response and returns its token, for
 * example in the login handler or a `GET /csrf-token` route.
 * @param {object} res
 * @param {Parameters<typeof issueCsrfCookie>[0]} [options]
 * @returns {string}
 */
export function issueCsrfToken(res, options) {
  const { token, setCookie } = issueCsrfCookie(options);
  const existing = res.getHeader("Set-Cookie");
  const cookies = existing === undefined ? [] : [].concat(existing);
  res.setHeader("Set-Cookie", [...cookies, setCookie]);
  return token;
}

// --- A03 Injection Defense ---------------------------------------------------

/**
 * Validates `req.body` (or `req.query`/`req.params`) against an
 * `InputValidator` schema; responds 400 with per-field errors otherwise.
 * @param {Parameters<typeof assertValidInput>[1]} schema
 * @param {Parameters<typeof assertValidInput>[2] & {source?: "body"|"query"|"params"}} [options]
 */
export function validate(schema, { source = "body", ...options } = {}) {
  return middleware((req) => {
    assertValidInput(req[source], schema, options);
  });
}

/**
 * Replaces the listed string fields of `req.body` with sanitized HTML. Only
 * the body: `req.query` is a read-only getter in Express 5.
 * @param {string[]} fields
 * @param {Parameters<typeof sanitizeFields>[2]} [options]
 */
export function sanitizeBody(fields, options) {
  return middleware((req) => {
    req.body = sanitizeFields(req.body, fields, options);
  });
}

// --- A10 SSRF Defense --------------------------------------------------------

/**
 * Checks a caller-supplied URL before the route requests it, and stores the
 * parsed result on `req.owl.outboundUrl`. Still make the request through
 * `SafeFetcher` so redirects and DNS rebinding are covered too.
 * @param {(req: any) => unknown} getUrl e.g. `(req) => req.body.webhookUrl`
 * @param {Parameters<typeof assertSafeOutboundUrl>[1]} [options]
 */
export function guardOutboundUrl(getUrl, options) {
  return middleware(async (req) => {
    owlState(req).outboundUrl = await assertSafeOutboundUrl(getUrl(req), options);
  });
}

// --- Errors + A09 Logging & Monitoring ---------------------------------------

/**
 * Error-handling middleware: maps `SecurityError`s to 400/401/403 JSON
 * responses, hides the message of anything that would be a 500, and logs each
 * failure through `logger` (a `SecurityLogger`, which redacts). Register it
 * after all routes.
 *
 * @param {{logger?: {warn: Function, error: Function}, exposeMessages?: boolean}} [options]
 */
export function errorHandler({ logger, exposeMessages } = {}) {
  // Express recognizes error handlers by their four declared parameters.
  return function owlErrorHandler(error, req, res, next) {
    logRequestError(logger, error, req);
    if (res.headersSent) {
      next(error);
      return;
    }
    const { status, headers, body } = toErrorResponse(error, { exposeMessages });
    const payload = JSON.stringify(body);
    res.statusCode = status;
    for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Length", Buffer.byteLength(payload));
    res.end(payload);
  };
}
