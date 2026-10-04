import { assertPermission, authenticate, getCookieValues, toPermissionChecker } from "@owasp-webshield/node";

// What `authenticate()` throws when there is no usable token; `getSession()`
// turns these into `null`, and lets anything else (a broken store) propagate.
const NO_SESSION_CODES = new Set(["AUTH_REQUIRED", "TOKEN_EXPIRED"]);

/**
 * A `getToken` for `authenticate()` / `withOwl({ auth })` that reads the session
 * token from a cookie instead of the `Authorization` header, which is how a
 * browser authenticates page loads and Server Actions. A cookie sent more than
 * once (cookie tossing) counts as no token.
 * @param {string} name
 * @returns {(req: any) => string | null}
 */
export function cookieToken(name) {
  return function getCookieToken(req) {
    const values = getCookieValues(req, name);
    return values.length === 1 && values[0] ? values[0] : null;
  };
}

/**
 * The server-side auth helpers, reading the request headers through
 * `getHeaders` (`headers()` from next/headers in `@owasp-webshield/next/server`).
 * @param {() => any} getHeaders
 * @param {{
 *   verifyToken: NonNullable<Parameters<typeof authenticate>[1]>["verifyToken"],
 *   getToken?: (req: any) => string | null,
 *   checker?: object
 * }} options
 */
export function createServerAuthWith(getHeaders, { verifyToken, getToken, checker }) {
  // Resolved now, so a misconfigured checker fails when the module loads.
  const permissionChecker = checker ? toPermissionChecker(checker) : undefined;

  /**
   * The session for the current request; throws `AUTH_REQUIRED` without one.
   * @returns {Promise<{userId: string, roles: string[], metadata: Record<string, any>}>}
   */
  async function requireSession() {
    return authenticate({ headers: await getHeaders() }, { verifyToken, getToken });
  }

  /**
   * The session for the current request, or `null` without one.
   * @returns {Promise<{userId: string, roles: string[], metadata: Record<string, any>} | null>}
   */
  async function getSession() {
    try {
      return await requireSession();
    } catch (error) {
      if (NO_SESSION_CODES.has(error?.code)) return null;
      throw error;
    }
  }

  /**
   * The session, if one of its roles has `action` on `resource`; throws
   * `AUTH_REQUIRED` or `ACCESS_DENIED` otherwise. Needs `checker`.
   * @param {string} action
   * @param {string} resource
   */
  async function requirePermission(action, resource) {
    const session = await requireSession();
    assertPermission({ session, action, resource }, permissionChecker);
    return session;
  }

  return { getSession, requireSession, requirePermission };
}
