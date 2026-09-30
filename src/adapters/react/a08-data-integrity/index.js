import React from "react";
import { CSRFTokenManager, HTTPClient } from "@owasp-webshield/core";

/**
 * Hook that returns a configured HTTPClient with CSRF and auth token support.
 */
export function useSecureHttpClient({ baseUrl = "", tokenProvider = null, fetchImpl } = {}) {
  const csrfManager = React.useMemo(() => {
    const manager = new CSRFTokenManager();
    manager.rotateToken();
    return manager;
  }, []);

  return React.useMemo(
    () =>
      new HTTPClient({
        baseUrl,
        csrfManager,
        tokenProvider,
        fetchImpl
      }),
    [baseUrl, csrfManager, tokenProvider, fetchImpl]
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