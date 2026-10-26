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
export function applySecurityHeaders<T extends Response>(response: T, overrides?: Record<string, string | false | null>): T | Response;
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
export function securityHeadersConfig(overrides?: Record<string, string | false | null>, { source, dev }?: {
    source?: string;
    dev?: boolean;
}): Array<{
    source: string;
    headers: Array<{
        key: string;
        value: string;
    }>;
}>;
/**
 * Sets a fresh double-submit CSRF cookie (`XSRF-TOKEN` by default) on the
 * response and returns its token, for example in the login route or a
 * `GET /api/csrf` route.
 * @param {Response} response a `Response` or `NextResponse`
 * @param {Parameters<typeof issueCsrfCookie>[0]} [options]
 * @returns {string}
 */
export function issueCsrfToken(response: Response, options?: Parameters<typeof issueCsrfCookie>[0]): string;
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
export function ensureCsrfCookie(request: Request, response: Response, options?: Parameters<typeof issueCsrfCookie>[0]): string;
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
export function errorResponse(error: unknown, { request, logger, exposeMessages, securityHeaders }?: {
    request?: Request;
    logger?: {
        warn: Function;
        error: Function;
    };
    exposeMessages?: boolean;
    securityHeaders?: Record<string, string | false | null> | false;
}): Response;
import { issueCsrfToken as issueCsrfCookie } from "@owasp-webshield/node";
