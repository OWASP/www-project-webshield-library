export function isSafeMethod(req: any): boolean;
/**
 * A new random CSRF token (base64url, 32 bytes of entropy by default).
 * @param {{tokenLength?: number}} [options]
 * @returns {string}
 */
export function generateCsrfToken({ tokenLength }?: {
    tokenLength?: number;
}): string;
/**
 * Issues a token for the double-submit cookie pattern: send `setCookie` as a
 * `Set-Cookie` header, and the browser echoes the cookie's value back in the
 * `X-CSRF-Token` header. The cookie can't be HttpOnly, since script has to read it.
 *
 * @param {{cookieName?: string, cookie?: Parameters<typeof serializeCookie>[2], tokenLength?: number}} [options]
 * @returns {{token: string, setCookie: string}}
 */
export function issueCsrfToken({ cookieName, cookie, tokenLength }?: {
    cookieName?: string;
    cookie?: Parameters<typeof serializeCookie>[2];
    tokenLength?: number;
}): {
    token: string;
    setCookie: string;
};
/**
 * Validates the CSRF token of a state-changing request; GET, HEAD and OPTIONS
 * pass without one. The comparison is `CSRFTokenManager.validate()`'s
 * constant-time check.
 *
 * Two ways to supply the expected token:
 * - `getExpectedToken(req)`: the synchronizer-token pattern, where the token is
 *   stored in the user's server-side session. Preferred when there is a session.
 * - otherwise, the double-submit cookie (`cookieName`). The request is rejected
 *   if the cookie arrives more than once, which is what a sibling subdomain
 *   planting its own copy (cookie tossing) looks like. A `__Host-` cookie name
 *   blocks that at the browser too.
 *
 * @param {any} req a Node IncomingMessage, an Express request or a Fetch Request
 * @param {{
 *   getExpectedToken?: (req: any) => string|null|undefined|Promise<string|null|undefined>,
 *   cookieName?: string,
 *   headerName?: string
 * }} [options]
 * @returns {Promise<boolean>} true when checked, false when skipped (safe method)
 */
export function verifyCsrf(req: any, { getExpectedToken, cookieName, headerName }?: {
    getExpectedToken?: (req: any) => string | null | undefined | Promise<string | null | undefined>;
    cookieName?: string;
    headerName?: string;
}): Promise<boolean>;
export const DEFAULT_CSRF_COOKIE: "XSRF-TOKEN";
export const DEFAULT_CSRF_HEADER: "x-csrf-token";
import { serializeCookie } from "../http/cookies.js";
