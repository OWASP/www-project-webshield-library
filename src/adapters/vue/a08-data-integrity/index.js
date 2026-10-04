import { computed, toValue } from "vue";
import { CSRFTokenManager, HTTPClient } from "@owasp-webshield/core";

/**
 * An `HTTPClient` with CSRF and auth token support; rebuilt when a ref/getter
 * `options` changes.
 *
 * The CSRF token must come from the server, which is the side that validates it:
 * - by default it is read from the `XSRF-TOKEN` cookie on every request
 *   (double-submit cookie pattern, the default of `@owasp-webshield/express`;
 *   set `csrfCookieName` for another name), or
 * - pass a `csrfManager` holding a server-issued token (`csrfManager.setToken(token)`).
 * Pass `csrfCookieName: null` and no `csrfManager` to send no CSRF header.
 *
 * @param {import("vue").MaybeRefOrGetter<{
 *   baseUrl?: string,
 *   tokenProvider?: (() => string | null) | null,
 *   fetchImpl?: typeof fetch,
 *   csrfManager?: CSRFTokenManager | null,
 *   csrfCookieName?: string | null,
 *   allowedOrigins?: string[],
 *   outboundRequestPolicy?: object
 * }>} [options]
 * @returns {import("vue").ComputedRef<HTTPClient>}
 */
export function useSecureHttpClient(options = {}) {
  return computed(() => {
    const {
      baseUrl = "",
      tokenProvider = null,
      fetchImpl,
      csrfManager = null,
      csrfCookieName = "XSRF-TOKEN",
      allowedOrigins,
      outboundRequestPolicy
    } = toValue(options) || {};
    return new HTTPClient({
      baseUrl,
      csrfManager: csrfManager || (csrfCookieName ? CSRFTokenManager.fromCookie(csrfCookieName) : null),
      tokenProvider,
      fetchImpl,
      allowedOrigins,
      outboundRequestPolicy
    });
  });
}

/**
 * `fetch` init with request-side hardening. X-Frame-Options/nosniff are
 * response headers and must be set by the server.
 * @param {RequestInit} [init]
 */
export function withSecurityHeaders(init = {}) {
  return {
    credentials: "same-origin",
    referrerPolicy: "strict-origin-when-cross-origin",
    ...init,
    headers: { ...(init.headers || {}) }
  };
}
