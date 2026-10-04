import { SecurityError, SecurityErrorCode } from "@owasp-webshield/core";
import { getHeader } from "../http/request.js";

// RFC 6750 b64token, which also covers JWTs and opaque session ids.
const BEARER_PATTERN = /^Bearer +([A-Za-z0-9\-._~+/]+=*) *$/i;

/**
 * The token from an `Authorization: Bearer <token>` header, or null.
 * @param {any} req
 * @returns {string | null}
 */
export function extractBearerToken(req) {
  const header = getHeader(req, "authorization");
  if (typeof header !== "string") return null;
  const match = BEARER_PATTERN.exec(header);
  return match ? match[1] : null;
}

/**
 * Same shape `AuthManager.setSession()` stores, so session objects look the
 * same on the server as they do in the browser adapters.
 */
function normalizeSession(session) {
  return {
    userId: String(session.userId),
    roles: Array.isArray(session.roles) ? session.roles.map(String) : [],
    metadata: session.metadata || {}
  };
}

/**
 * Authenticates one request. The server holds no session state of its own:
 * `verifyToken` is where the app checks the token (JWT verification, a session
 * store lookup, token introspection) and returns that user's session, or null.
 * Unlike `AuthManager`, which holds the single session of a browser tab, every
 * call here is independent, so concurrent requests from different users never
 * share state.
 *
 * @param {any} req a Node IncomingMessage, an Express request or a Fetch Request
 * @param {{
 *   verifyToken: (token: string, req: any) => ({userId: string|number, roles?: string[], metadata?: Record<string, any>} | null | Promise<{userId: string|number, roles?: string[], metadata?: Record<string, any>} | null>),
 *   getToken?: (req: any) => string|null
 * }} options
 * @returns {Promise<{userId: string, roles: string[], metadata: Record<string, any>}>}
 */
export async function authenticate(req, { verifyToken, getToken = extractBearerToken } = {}) {
  if (typeof verifyToken !== "function") {
    throw new SecurityError(SecurityErrorCode.MISCONFIGURATION, "authenticate() requires a verifyToken function");
  }
  const token = getToken(req);
  if (!token) {
    throw new SecurityError(SecurityErrorCode.AUTH_REQUIRED, "Missing bearer token");
  }
  const session = await verifyToken(token, req);
  if (!session || session.userId === undefined || session.userId === null) {
    throw new SecurityError(SecurityErrorCode.AUTH_REQUIRED, "Invalid or expired token");
  }
  return normalizeSession(session);
}
