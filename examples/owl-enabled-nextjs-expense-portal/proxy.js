import { NextResponse } from "next/server";
import { ensureCsrfCookie, guardCsrf } from "@owasp-webshield/next";

/**
 * A08, first gate. Every state-changing API request must carry the XSRF-TOKEN
 * cookie's value in X-CSRF-Token (double submit), including sign-in, which has
 * no session yet: without it, another site could sign the victim in to the
 * attacker's account (login CSRF). Page loads get the cookie if they lack it.
 *
 * Authenticated routes then also check the token against the session
 * (lib/auth.js), and every route does its own auth and permission checks:
 * this proxy is a first gate, not the only one. Server Actions are POSTs to
 * page URLs and are protected by Next.js's own Origin check.
 */
export async function proxy(request) {
  if (request.nextUrl.pathname.startsWith("/api/")) {
    return (await guardCsrf(request)) ?? NextResponse.next();
  }
  const response = NextResponse.next();
  ensureCsrfCookie(request, response);
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"]
};
