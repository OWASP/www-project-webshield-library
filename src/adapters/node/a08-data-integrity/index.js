import { CSRFTokenManager, SecurityError, SecurityErrorCode } from "@owasp-webshield/core";
import { getCookieValues, serializeCookie } from "../http/cookies.js";
import { getHeader, getMethod } from "../http/request.js";

// Same defaults as the browser side: `CSRFTokenManager.fromCookie()` and the
// React adapter's `useSecureHttpClient()` read "XSRF-TOKEN" and send "X-CSRF-Token".
export const DEFAULT_CSRF_COOKIE = "XSRF-TOKEN";
export const DEFAULT_CSRF_HEADER = "x-csrf-token";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function isSafeMethod(req) {
  return SAFE_METHODS.has(getMethod(req));
}

/**
 * A new random CSRF token (base64url, 32 bytes of entropy by default).
 */
export function generateCsrfToken({ tokenLength } = {}) {
  return new CSRFTokenManager({ tokenLength }).generateToken();
}

/**
 * Issues a token for the double-submit cookie pattern: send `setCookie` as a
 * `Set-Cookie` header, and the browser echoes the cookie's value back in the
 * `X-CSRF-Token` header. The cookie can't be HttpOnly, since script has to read it.
 *
 * @param {{cookieName?: string, cookie?: Parameters<typeof serializeCookie>[2], tokenLength?: number}} [options]
 * @returns {{token: string, setCookie: string}}
 */
export function issueCsrfToken({ cookieName = DEFAULT_CSRF_COOKIE, cookie = {}, tokenLength } = {}) {
  const token = generateCsrfToken({ tokenLength });
  return { token, setCookie: serializeCookie(cookieName, token, { ...cookie, httpOnly: false }) };
}

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
 * @param {object} req
 * @param {{
 *   getExpectedToken?: (req: object) => string|null|undefined|Promise<string|null|undefined>,
 *   cookieName?: string,
 *   headerName?: string
 * }} [options]
 * @returns {Promise<boolean>} true when checked, false when skipped (safe method)
 */
export async function verifyCsrf(req, { getExpectedToken, cookieName = DEFAULT_CSRF_COOKIE, headerName = DEFAULT_CSRF_HEADER } = {}) {
  if (isSafeMethod(req)) return false;

  let expected;
  if (getExpectedToken) {
    expected = await getExpectedToken(req);
  } else {
    const values = getCookieValues(req, cookieName);
    if (values.length > 1) {
      throw new SecurityError(SecurityErrorCode.CSRF_INVALID, "CSRF cookie sent more than once");
    }
    expected = values[0];
  }

  const manager = new CSRFTokenManager({ storage: { get: () => expected || null, set: () => {} } });
  return manager.validate(getHeader(req, headerName));
}
