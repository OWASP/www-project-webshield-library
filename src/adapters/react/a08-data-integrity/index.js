import React from "react";
import { CSRFTokenManager, HTTPClient } from "@owasp-webshield/core";
import { useStableValue } from "../useStableValue.js";

/**
 * Hook that returns a configured HTTPClient with CSRF and auth token support.
 *
 * The CSRF token must come from the server, which is the side that validates it:
 * - by default it is read from the `XSRF-TOKEN` cookie on every request
 *   (double-submit cookie pattern; set `csrfCookieName` for another name), or
 * - pass a `csrfManager` holding a server-issued token (`csrfManager.setToken(token)`).
 * Pass `csrfCookieName: null` and no `csrfManager` to send no CSRF header.
 */
export function useSecureHttpClient({
  baseUrl = "",
  tokenProvider = null,
  fetchImpl,
  csrfManager = null,
  csrfCookieName = "XSRF-TOKEN",
  allowedOrigins,
  outboundRequestPolicy
} = {}) {
  const csrf = React.useMemo(
    () => csrfManager || (csrfCookieName ? CSRFTokenManager.fromCookie(csrfCookieName) : null),
    [csrfManager, csrfCookieName]
  );
  const stableOrigins = useStableValue(allowedOrigins);

  return React.useMemo(
    () =>
      new HTTPClient({
        baseUrl,
        csrfManager: csrf,
        tokenProvider,
        fetchImpl,
        allowedOrigins: stableOrigins,
        outboundRequestPolicy
      }),
    [baseUrl, csrf, tokenProvider, fetchImpl, stableOrigins, outboundRequestPolicy]
  );
}

// Request-side hardening only: X-Frame-Options/nosniff are response headers and must be set by the server.
export function withSecurityHeaders(init = {}) {
  return {
    credentials: "same-origin",
    referrerPolicy: "strict-origin-when-cross-origin",
    ...init,
    headers: { ...(init.headers || {}) }
  };
}