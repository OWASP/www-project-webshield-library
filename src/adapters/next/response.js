import {
  DEFAULT_CSRF_COOKIE,
  getCookieValues,
  issueCsrfToken as issueCsrfCookie,
  logRequestError,
  securityHeaders as buildSecurityHeaders,
  toErrorResponse
} from "@owasp-webshield/node";

// --- A05 Security Misconfiguration -------------------------------------------

function setMissing(headers, values) {
  for (const [name, value] of Object.entries(values)) {
    if (!headers.has(name)) headers.set(name, value);
  }
}

/**
 * Adds the security headers (see `DEFAULT_SECURITY_HEADERS`, made for a JSON
 * API) that `response` doesn't already have, so a header the route set itself
 * wins. Returns `response`, or a copy of it when its headers are immutable
 * (`Response.redirect()`, a proxied `fetch()` response).
 * @template {Response} T
 * @param {T} response
 * @param {Record<string, string|false|null>} [overrides] `false` drops a header
 * @returns {T | Response}
 */
export function applySecurityHeaders(response, overrides) {
  const values = buildSecurityHeaders(overrides);
  try {
    setMissing(response.headers, values);
    return response;
  } catch (error) {
    // By name, not instanceof: the Edge runtime runs route code in its own realm.
    if (error?.name !== "TypeError") throw error;
    const copy = new Response(response.body, response);
    setMissing(copy.headers, values);
    return copy;
  }
}

/**
 * The CSP from the Next.js security guide for apps that don't use nonces.
 * Next.js inlines its bootstrap scripts, so `script-src` needs 'unsafe-inline';
 * the dev server also evaluates code for Fast Refresh.
 */
function pageContentSecurityPolicy(dev) {
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${dev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' blob: data:",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests"
  ].join("; ");
}

/**
 * The security headers in the shape `headers()` in `next.config.js` returns,
 * for pages as well as route handlers. The default CSP allows what a Next.js
 * page needs (see the README); pass `"Content-Security-Policy"` to use your own,
 * such as a nonce-based policy set in middleware instead.
 *
 * @param {Record<string, string|false|null>} [overrides] `false` drops a header
 * @param {{source?: string, dev?: boolean}} [options] `dev` defaults to
 *   `NODE_ENV === "development"`
 * @returns {Array<{source: string, headers: Array<{key: string, value: string}>}>}
 */
export function securityHeadersConfig(overrides = {}, { source = "/(.*)", dev = process.env.NODE_ENV === "development" } = {}) {
  const values = buildSecurityHeaders({ "Content-Security-Policy": pageContentSecurityPolicy(dev), ...overrides });
  return [{ source, headers: Object.entries(values).map(([key, value]) => ({ key, value })) }];
}

// --- A08 Data Integrity (CSRF) -----------------------------------------------

/**
 * `NextResponse.cookies.set()` options matching `serializeCookie()`'s defaults,
 * with HttpOnly off so the browser can read the token.
 */
function nextCookieOptions({ path = "/", domain, maxAge, secure = true, sameSite = "Strict" }) {
  const options = { path, secure, httpOnly: false, sameSite: String(sameSite).toLowerCase() };
  if (domain) options.domain = domain;
  if (Number.isFinite(maxAge)) options.maxAge = Math.floor(maxAge);
  return options;
}

/**
 * Sets a fresh double-submit CSRF cookie (`XSRF-TOKEN` by default) on the
 * response and returns its token, for example in the login route or a
 * `GET /api/csrf` route.
 * @param {Response} response a `Response` or `NextResponse`
 * @param {Parameters<typeof issueCsrfCookie>[0]} [options]
 * @returns {string}
 */
export function issueCsrfToken(response, options = {}) {
  // Builds the cookie first, which rejects an invalid name or attribute combination.
  const { token, setCookie } = issueCsrfCookie(options);
  if (typeof response.cookies?.set === "function") {
    // NextResponse keeps its own cookie list and rewrites Set-Cookie from it on
    // every `cookies.set()`, which would drop a header appended directly.
    response.cookies.set(options.cookieName || DEFAULT_CSRF_COOKIE, token, nextCookieOptions(options.cookie || {}));
  } else {
    response.headers.append("Set-Cookie", setCookie);
  }
  return token;
}

/**
 * Returns the request's CSRF token, issuing one on `response` when the request
 * has none, so the browser has a token before its first state-changing request.
 * Call it from middleware on page requests. A request carrying the cookie more
 * than once gets a fresh one; `verifyCsrf()` rejects the duplicate either way.
 * @param {Request} request
 * @param {Response} response
 * @param {Parameters<typeof issueCsrfCookie>[0]} [options]
 * @returns {string}
 */
export function ensureCsrfCookie(request, response, options = {}) {
  const values = getCookieValues(request, options.cookieName || DEFAULT_CSRF_COOKIE);
  if (values.length === 1 && values[0]) return values[0];
  return issueCsrfToken(response, options);
}

// --- Errors + A09 Logging & Monitoring ---------------------------------------

/**
 * The JSON response for a thrown value: `SecurityError`s become 400/401/403
 * with their code in `error`, and a 500 never includes the error's message.
 * Logs the failure through `logger` (a `SecurityLogger`, which redacts).
 *
 * @param {unknown} error
 * @param {{
 *   request?: Request,
 *   logger?: {warn: Function, error: Function},
 *   exposeMessages?: boolean,
 *   securityHeaders?: Record<string, string|false|null> | false
 * }} [options]
 * @returns {Response}
 */
export function errorResponse(error, { request, logger, exposeMessages, securityHeaders } = {}) {
  logRequestError(logger, error, request);
  const { status, headers, body } = toErrorResponse(error, { exposeMessages });
  const response = Response.json(body, { status, headers });
  return securityHeaders === false ? response : applySecurityHeaders(response, securityHeaders);
}
