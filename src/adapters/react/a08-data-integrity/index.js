import React from "react";
import { CSRFTokenManager } from "../../../core/a08-data-integrity/CSRFTokenManager.js";
import { HTTPClient } from "../../../core/a08-data-integrity/HTTPClient.js";

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

export function withSecurityHeaders(init = {}) {
  return {
    ...init,
    headers: {
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      ...(init.headers || {})
    }
  };
}