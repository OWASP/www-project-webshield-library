/**
 * Hook that returns a configured HTTPClient with CSRF and auth token support.
 *
 * The CSRF token must come from the server, which is the side that validates it:
 * - by default it is read from the `XSRF-TOKEN` cookie on every request
 *   (double-submit cookie pattern; set `csrfCookieName` for another name), or
 * - pass a `csrfManager` holding a server-issued token (`csrfManager.setToken(token)`).
 * Pass `csrfCookieName: null` and no `csrfManager` to send no CSRF header.
 */
export function useSecureHttpClient({ baseUrl, tokenProvider, fetchImpl, csrfManager, csrfCookieName, allowedOrigins, outboundRequestPolicy }?: {
    baseUrl?: string;
    tokenProvider?: any;
    csrfManager?: any;
    csrfCookieName?: string;
}): any;
/**
 * Request-side hardening only: X-Frame-Options/nosniff are response headers and must be set by the server.
 * @param {RequestInit} [init]
 * @returns {RequestInit & {headers: Record<string, string>}}
 */
export function withSecurityHeaders(init?: RequestInit): RequestInit & {
    headers: Record<string, string>;
};
