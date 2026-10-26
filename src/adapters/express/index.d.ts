/// <reference path="./request.d.ts" />
/**
 * Sets the security response headers (see `DEFAULT_SECURITY_HEADERS`) and removes
 * `X-Powered-By`. Register it first, so error responses get the headers too.
 * @param {Record<string, string|false|null>} [overrides] `false` drops a header
 */
export function securityHeaders(overrides?: Record<string, string | false | null>): (_req: any, res: any, next: any) => void;
/**
 * Authenticates the request with `verifyToken` and stores the session on
 * `req.owl.session`; responds 401 through `errorHandler()` otherwise.
 * @param {Parameters<typeof authenticate>[1]} options
 */
export function requireAuth(options: Parameters<typeof authenticate>[1]): (req: any, res: any, next: any) => void;
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
export function requirePermission(action: string, resource: string | ((req: any) => string), checkerSource: object): (req: any, res: any, next: any) => void;
/**
 * Rejects POST/PUT/PATCH/DELETE requests without a valid `X-CSRF-Token`
 * header. By default the expected token is the double-submit `XSRF-TOKEN`
 * cookie set by `issueCsrfToken()`; pass `getExpectedToken` to check a token
 * stored in the server-side session instead.
 * @param {Parameters<typeof verifyCsrf>[1]} [options]
 */
export function csrfProtection(options?: Parameters<typeof verifyCsrf>[1]): (req: any, res: any, next: any) => void;
/**
 * Sets a fresh CSRF cookie on the response and returns its token, for
 * example in the login handler or a `GET /csrf-token` route.
 * @param {object} res
 * @param {Parameters<typeof issueCsrfCookie>[0]} [options]
 * @returns {string}
 */
export function issueCsrfToken(res: object, options?: Parameters<typeof issueCsrfCookie>[0]): string;
/**
 * Validates `req.body` (or `req.query`/`req.params`) against an
 * `InputValidator` schema; responds 400 with per-field errors otherwise.
 * @param {Parameters<typeof assertValidInput>[1]} schema
 * @param {Parameters<typeof assertValidInput>[2] & {source?: "body"|"query"|"params"}} [options]
 */
export function validate(schema: Parameters<typeof assertValidInput>[1], { source, ...options }?: Parameters<typeof assertValidInput>[2] & {
    source?: "body" | "query" | "params";
}): (req: any, res: any, next: any) => void;
/**
 * Replaces the listed string fields of `req.body` with sanitized HTML. Only
 * the body: `req.query` is a read-only getter in Express 5.
 * @param {string[]} fields
 * @param {Parameters<typeof sanitizeFields>[2]} [options]
 */
export function sanitizeBody(fields: string[], options?: Parameters<typeof sanitizeFields>[2]): (req: any, res: any, next: any) => void;
/**
 * Checks a caller-supplied URL before the route requests it, and stores the
 * parsed result on `req.owl.outboundUrl`. Still make the request through
 * `SafeFetcher` so redirects and DNS rebinding are covered too.
 * @param {(req: any) => unknown} getUrl e.g. `(req) => req.body.webhookUrl`
 * @param {Parameters<typeof assertSafeOutboundUrl>[1]} [options]
 */
export function guardOutboundUrl(getUrl: (req: any) => unknown, options?: Parameters<typeof assertSafeOutboundUrl>[1]): (req: any, res: any, next: any) => void;
/**
 * Error-handling middleware: maps `SecurityError`s to 400/401/403 JSON
 * responses, hides the message of anything that would be a 500, and logs each
 * failure through `logger` (a `SecurityLogger`, which redacts). Register it
 * after all routes.
 *
 * @param {{logger?: {warn: Function, error: Function}, exposeMessages?: boolean}} [options]
 */
export function errorHandler({ logger, exposeMessages }?: {
    logger?: {
        warn: Function;
        error: Function;
    };
    exposeMessages?: boolean;
}): (error: any, req: any, res: any, next: any) => void;
import { authenticate } from "@owasp-webshield/node";
import { verifyCsrf } from "@owasp-webshield/node";
import { issueCsrfToken as issueCsrfCookie } from "@owasp-webshield/node";
import { assertValidInput } from "@owasp-webshield/node";
import { sanitizeFields } from "@owasp-webshield/node";
import { assertSafeOutboundUrl } from "@owasp-webshield/node";
export { assertHardened, DEFAULT_SECURITY_HEADERS, generateCsrfToken, statusForSecurityError, toErrorResponse } from "@owasp-webshield/node";
