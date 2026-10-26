import { randomBytes } from "node:crypto";
import { generateCsrfToken } from "@owasp-webshield/next";

/**
 * A07: server-side sessions. The cookie holds a random 256-bit token with no
 * meaning of its own; the session lives only here and expires. Every page,
 * Server Action and route handler looks it up again, so signing out or expiry
 * takes effect on the next request.
 *
 * A08: each session gets its own CSRF token (synchronizer pattern). It is sent
 * to the browser in the XSRF-TOKEN cookie at sign-in and checked against the
 * session, not just against the cookie.
 *
 * In memory for the demo; use Redis or a database so sessions survive restarts
 * and work across instances.
 */
export function createSessionStore({ ttlMs = 30 * 60_000, now = () => Date.now() } = {}) {
  const sessions = new Map();

  return {
    create(user) {
      const token = randomBytes(32).toString("base64url");
      const csrfToken = generateCsrfToken();
      const expiresAt = now() + ttlMs;
      sessions.set(token, { userId: user.id, name: user.name, team: user.team, roles: user.roles, csrfToken, expiresAt });
      return { token, csrfToken, expiresAt };
    },

    /** The session in the shape `authenticate()` expects, or null. */
    lookup(token) {
      const session = sessions.get(token);
      if (!session) return null;
      if (session.expiresAt <= now()) {
        sessions.delete(token);
        return null;
      }
      const { userId, roles, ...metadata } = session;
      return { userId, roles, metadata: { ...metadata, token } };
    },

    destroy(token) {
      sessions.delete(token);
    }
  };
}
