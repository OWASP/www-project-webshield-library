/**
 * Hook that returns a configured HTTPClient with CSRF and auth token support.
 */
export function useSecureHttpClient({ baseUrl, tokenProvider, fetchImpl }?: {
    baseUrl?: string;
    tokenProvider?: any;
}): any;
export function withSecurityHeaders(init?: {}): {
    headers: any;
};
