import { randomBytes } from "node:crypto";

/**
 * A07: server-side sessions. The bearer token is a random 256-bit value with
 * no meaning of its own; the session it points to lives only on the server and
 * expires. `requireAuth({ verifyToken })` from @owasp-webshield/express calls
 * `lookup()` on every request, so every request is checked against this store.
 *
 * In-memory for the demo; use Redis or a database table in production so
 * sessions survive restarts and work across instances.
 */
export function createSessionStore({ ttlMs = 15 * 60_000, now = () => Date.now() } = {}) {
  const sessions = new Map();

  return {
    create(user, csrfToken) {
      const accessToken = randomBytes(32).toString("base64url");
      const expiresAt = now() + ttlMs;
      sessions.set(accessToken, { userId: user.id, name: user.name, roles: user.roles, csrfToken, expiresAt });
      return { accessToken, expiresAt };
    },

    // Returns the session in the shape requireAuth() expects, or null.
    lookup(accessToken) {
      const session = sessions.get(accessToken);
      if (!session) return null;
      if (session.expiresAt <= now()) {
        sessions.delete(accessToken);
        return null;
      }
      return {
        userId: session.userId,
        roles: session.roles,
        metadata: { accessToken, name: session.name, csrfToken: session.csrfToken, expiresAt: session.expiresAt }
      };
    },

    destroy(accessToken) {
      sessions.delete(accessToken);
    }
  };
}
