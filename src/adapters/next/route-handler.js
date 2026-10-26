import {
  assertPermission,
  assertSafeOutboundUrl,
  assertValidInput,
  authenticate,
  sanitizeFields,
  toPermissionChecker,
  verifyCsrf
} from "@owasp-webshield/node";
import { readJsonBody } from "./body.js";
import { applySecurityHeaders, errorResponse } from "./response.js";

// Next.js implements redirect(), notFound(), forbidden() and dynamic-rendering
// bailouts by throwing errors that it catches again further up. They must reach
// Next.js instead of becoming a 500. Mirrors `unstable_rethrow()` from
// next/navigation, which this package can't import without depending on Next.js.
const NEXT_CONTROL_FLOW_DIGEST =
  /^(?:NEXT_REDIRECT|NEXT_HTTP_ERROR_FALLBACK|NEXT_PRERENDER_INTERRUPTED|DYNAMIC_SERVER_USAGE|BAILOUT_TO_CLIENT_SIDE_RENDERING|HANGING_PROMISE_REJECTION)(?:;|$)/;
const REACT_POSTPONE = Symbol.for("react.postpone");

function isNextControlFlow(error) {
  if (typeof error !== "object" || error === null) return false;
  if (typeof error.digest === "string" && NEXT_CONTROL_FLOW_DIGEST.test(error.digest)) return true;
  if (error.$$typeof === REACT_POSTPONE) return true;
  return error instanceof Error && "cause" in error && isNextControlFlow(error.cause);
}

/**
 * @typedef {object} OwlRouteState What `withOwl()` checked, passed to the handler.
 * @property {any} [params] the route's resolved dynamic segments
 * @property {{userId: string, roles: string[], metadata: Record<string, any>}} [session] set by `auth`
 * @property {Record<string, string>} [query] set by `query`: the validated search params
 * @property {any} [body] set by `body`: the parsed, validated and sanitized JSON body
 * @property {URL} [outboundUrl] set by `outboundUrl`: the URL that passed the SSRF check
 */

/**
 * @typedef {object} WithOwlOptions
 * @property {Parameters<typeof authenticate>[1]} [auth] authenticates the request
 *   (A07); responds 401 without a valid token
 * @property {true | Parameters<typeof verifyCsrf>[1]} [csrf] rejects POST/PUT/PATCH/DELETE
 *   without a valid `X-CSRF-Token` header (A08)
 * @property {{action: string, resource: string | ((owl: OwlRouteState, request: Request) => string | Promise<string>), checker: object}} [permission]
 *   requires `action` on `resource` for a role of the session (A01). `checker` is a
 *   `PermissionChecker` or the object `createOwlClient()` returns. Needs `auth`.
 * @property {{schema: Parameters<typeof assertValidInput>[1]} & Parameters<typeof assertValidInput>[2]} [query]
 *   validates the search params (A03); a repeated parameter keeps its last value
 * @property {{schema?: Parameters<typeof assertValidInput>[1], sanitize?: string[], limit?: number, sanitizer?: NonNullable<Parameters<typeof sanitizeFields>[2]>["sanitizer"]} & Parameters<typeof assertValidInput>[2]} [body]
 *   parses the JSON body (`limit` in bytes, 100 KB by default), validates it against
 *   `schema` and sanitizes the `sanitize` fields (A03)
 * @property {{getUrl: (owl: OwlRouteState, request: Request) => unknown, guard?: NonNullable<Parameters<typeof assertSafeOutboundUrl>[1]>["guard"]}} [outboundUrl]
 *   checks a caller-supplied URL before the handler requests it (A10)
 * @property {Record<string, string|false|null> | false} [securityHeaders] header
 *   overrides, or `false` to add none (A05)
 * @property {{warn: Function, error: Function}} [logger] logs each failure (A09)
 * @property {boolean} [exposeMessages] `false` sends only the error code
 */

/**
 * Wraps an App Router route handler with OWL's checks. They run in this order,
 * and the first failure becomes a JSON error response (see `errorResponse()`):
 * auth, csrf, permission, query, body, outboundUrl. Errors the handler throws
 * are mapped the same way, except Next.js's own (`redirect()`, `notFound()`).
 * Every response gets the security headers it doesn't already set.
 *
 * @template {Request} R
 * @param {(request: R, context: any, owl: OwlRouteState) => Response | Promise<Response>} handler
 * @param {WithOwlOptions} [options]
 * @returns {(request: R, context?: any) => Promise<Response>}
 */
export function withOwl(handler, options = {}) {
  const { auth, csrf, permission, query, body, outboundUrl, securityHeaders, logger, exposeMessages } = options;
  // Resolved now, so a misconfigured checker fails when the route module loads.
  const checker = permission ? toPermissionChecker(permission.checker) : null;

  return async function owlRouteHandler(request, context) {
    let response;
    try {
      // `params` is a Promise since Next.js 15 and a plain object before.
      /** @type {OwlRouteState} */
      const owl = { params: await context?.params };
      if (auth) owl.session = await authenticate(request, auth);
      if (csrf) await verifyCsrf(request, csrf === true ? undefined : csrf);
      if (permission) {
        const resource = typeof permission.resource === "function" ? await permission.resource(owl, request) : permission.resource;
        assertPermission({ session: owl.session, action: permission.action, resource }, checker);
      }
      if (query) {
        const { schema, ...validation } = query;
        owl.query = assertValidInput(Object.fromEntries(new URL(request.url).searchParams), schema, validation);
      }
      if (body) {
        const { schema, sanitize, limit, sanitizer, ...validation } = body;
        let data = await readJsonBody(request, { limit });
        if (schema) data = assertValidInput(data, schema, validation);
        owl.body = sanitize ? sanitizeFields(data, sanitize, { sanitizer }) : data;
      }
      if (outboundUrl) {
        owl.outboundUrl = await assertSafeOutboundUrl(await outboundUrl.getUrl(owl, request), { guard: outboundUrl.guard });
      }
      response = await handler(request, context, owl);
    } catch (error) {
      if (isNextControlFlow(error)) throw error;
      return errorResponse(error, { request, logger, exposeMessages, securityHeaders });
    }
    // Anything else is Next.js's to report ("No response is returned from route handler").
    if (securityHeaders === false || !(response instanceof Response)) return response;
    return applySecurityHeaders(response, securityHeaders);
  };
}
