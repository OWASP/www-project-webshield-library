import { NextResponse } from "next/server";
import { withOwl } from "@owasp-webshield/next";
import { apiRoute, CSRF_COOKIE, SESSION_COOKIE } from "../../../lib/auth.js";
import { LOGIN_SCHEMA } from "../../../lib/policy.js";
import { portal } from "../../../lib/portal.js";
import { clientIp } from "../../../lib/rate-limit.js";

const cookieBase = { path: "/", secure: true, sameSite: "lax" };

/**
 * Sign in. There is no session yet, so CSRF is the double-submit cookie the
 * proxy issued on the sign-in page (login CSRF), checked again here.
 */
export const POST = withOwl(
  async (request, context, { body }) => {
    const { users, sessions, signInLimiter, logger } = portal();

    // A07: per-IP limit on failed attempts, on top of the per-account lockout.
    const ip = clientIp(request.headers);
    if (!signInLimiter.allows(ip)) {
      logger.warn("security.rate_limited", { path: "/api/session", ip });
      return Response.json({ error: "rate_limited", message: "Too many failed sign-ins. Try again in a minute." }, { status: 429 });
    }

    let user;
    try {
      user = users.verify(body.username, body.password);
    } catch (error) {
      signInLimiter.hit(ip);
      logger.warn("auth.login_failed", { username: body.username, ip, reason: error.message });
      throw error;
    }

    // A07: a fresh session id at every sign-in (no session fixation); any
    // session the browser already had is ended.
    const previous = request.cookies.get(SESSION_COOKIE)?.value;
    if (previous) sessions.destroy(previous);
    const { token, csrfToken, expiresAt } = sessions.create(user);
    logger.info("auth.login", { userId: user.id, ip });

    const response = NextResponse.json({ user, expiresAt }, { status: 201 });
    const maxAge = Math.floor((expiresAt - Date.now()) / 1000);
    response.cookies.set(SESSION_COOKIE, token, { ...cookieBase, httpOnly: true, maxAge });
    // A08: the session's own CSRF token, readable by script so useSecureHttpClient() can send it.
    response.cookies.set(CSRF_COOKIE, csrfToken, { ...cookieBase, httpOnly: false, maxAge });
    return response;
  },
  { csrf: true, body: { schema: LOGIN_SCHEMA, allowUnknownFields: false }, logger: portal().logger }
);

/** Sign out: the session ends on the server, not just in the browser. */
export const DELETE = apiRoute(async (request, context, { session }) => {
  portal().sessions.destroy(session.metadata.token);
  portal().logger.info("auth.logout", { userId: session.userId });
  const response = new NextResponse(null, { status: 204 });
  response.cookies.set(SESSION_COOKIE, "", { ...cookieBase, httpOnly: true, maxAge: 0 });
  response.cookies.set(CSRF_COOKIE, "", { ...cookieBase, httpOnly: false, maxAge: 0 });
  return response;
});
