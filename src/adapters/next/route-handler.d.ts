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
export function withOwl<R extends Request>(handler: (request: R, context: any, owl: OwlRouteState) => Response | Promise<Response>, options?: WithOwlOptions): (request: R, context?: any) => Promise<Response>;
/**
 * What `withOwl()` checked, passed to the handler.
 */
export type OwlRouteState = {
    /**
     * the route's resolved dynamic segments
     */
    params?: any;
    /**
     * set by `auth`
     */
    session?: {
        userId: string;
        roles: string[];
        metadata: Record<string, any>;
    };
    /**
     * set by `query`: the validated search params
     */
    query?: Record<string, string>;
    /**
     * set by `body`: the parsed, validated and sanitized JSON body
     */
    body?: any;
    /**
     * set by `outboundUrl`: the URL that passed the SSRF check
     */
    outboundUrl?: URL;
};
export type WithOwlOptions = {
    /**
     * authenticates the request
     * (A07); responds 401 without a valid token
     */
    auth?: Parameters<typeof authenticate>[1];
    /**
     * rejects POST/PUT/PATCH/DELETE
     * without a valid `X-CSRF-Token` header (A08)
     */
    csrf?: true | Parameters<typeof verifyCsrf>[1];
    /**
     * requires `action` on `resource` for a role of the session (A01). `checker` is a
     * `PermissionChecker` or the object `createOwlClient()` returns. Needs `auth`.
     */
    permission?: {
        action: string;
        resource: string | ((owl: OwlRouteState, request: Request) => string | Promise<string>);
        checker: object;
    };
    /**
     * validates the search params (A03); a repeated parameter keeps its last value
     */
    query?: {
        schema: Parameters<typeof assertValidInput>[1];
    } & Parameters<typeof assertValidInput>[2];
    /**
     * parses the JSON body (`limit` in bytes, 100 KB by default), validates it against
     * `schema` and sanitizes the `sanitize` fields (A03)
     */
    body?: {
        schema?: Parameters<typeof assertValidInput>[1];
        sanitize?: string[];
        limit?: number;
        sanitizer?: NonNullable<Parameters<typeof sanitizeFields>[2]>["sanitizer"];
    } & Parameters<typeof assertValidInput>[2];
    /**
     * checks a caller-supplied URL before the handler requests it (A10)
     */
    outboundUrl?: {
        getUrl: (owl: OwlRouteState, request: Request) => unknown;
        guard?: NonNullable<Parameters<typeof assertSafeOutboundUrl>[1]>["guard"];
    };
    /**
     * header
     * overrides, or `false` to add none (A05)
     */
    securityHeaders?: Record<string, string | false | null> | false;
    /**
     * logs each failure (A09)
     */
    logger?: {
        warn: Function;
        error: Function;
    };
    /**
     * `false` sends only the error code
     */
    exposeMessages?: boolean;
};
import { authenticate } from "@owasp-webshield/node";
import { verifyCsrf } from "@owasp-webshield/node";
import { assertValidInput } from "@owasp-webshield/node";
import { sanitizeFields } from "@owasp-webshield/node";
import { assertSafeOutboundUrl } from "@owasp-webshield/node";
