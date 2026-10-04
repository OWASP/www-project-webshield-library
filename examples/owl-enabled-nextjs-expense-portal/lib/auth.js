import { redirect } from "next/navigation";
import { SecurityError } from "@owasp-webshield/core";
import { cookieToken, withOwl } from "@owasp-webshield/next";
import { createServerAuth } from "@owasp-webshield/next/server";
import { portal } from "./portal.js";

// A07: `__Host-` cookies are only accepted over HTTPS (or on localhost), with
// Path=/ and no Domain, so a sibling subdomain can't set or overwrite them.
export const SESSION_COOKIE = "__Host-expense_session";
export const CSRF_COOKIE = "XSRF-TOKEN";

const getToken = cookieToken(SESSION_COOKIE);
const verifyToken = (token) => portal().sessions.lookup(token);

/** For Server Components and Server Actions, which have no request object. */
export const { getSession, requireSession } = createServerAuth({ verifyToken, getToken, checker: portal().owl });

/** A page's session; signed-out visitors are sent to the sign-in page. */
export async function pageSession() {
  const session = await getSession();
  if (!session) redirect("/login");
  return session;
}

/**
 * The OWL checks every authenticated API route runs: the session cookie (A07),
 * the session's own CSRF token in X-CSRF-Token for writes (A08, synchronizer
 * pattern) and a redacting audit log of every failure (A09). Routes add
 * `permission`, `body`, `outboundUrl`... as they need.
 */
export function apiRoute(handler, options = {}) {
  return withOwl(handler, {
    auth: { verifyToken, getToken },
    csrf: { getExpectedToken: (request) => verifyToken(getToken(request))?.metadata.csrfToken },
    logger: portal().logger,
    ...options
  });
}

/**
 * Runs a Server Action body for the signed-in user. A Server Action is a public
 * POST endpoint, so it checks the session itself; the claims service then
 * checks the permission. Security failures come back as form state for
 * `useActionState`, everything else is thrown (and shown by Next.js's error page).
 */
export async function runAction(body) {
  const session = await getSession();
  if (!session) return { error: "Your session has ended. Sign in again." };
  try {
    return { ok: true, ...(await body(session)) };
  } catch (error) {
    const fieldErrors = error?.details?.errors;
    if (error instanceof SecurityError || error?.status === 404) {
      portal().logger.warn("action.rejected", { userId: session.userId, code: error.code ?? "NOT_FOUND", message: error.message });
      return { error: fieldErrors?.[0]?.message ?? error.message, fields: fieldErrors };
    }
    throw error;
  }
}
