/**
 * Auth middleware utilities for use with fetch / third-party HTTP clients.
 */

export interface AuthMiddlewareOptions {
  getToken: () => string | null;
  tokenType?: string;
  onTokenExpired?: () => void;
}

/**
 * Returns a fetch wrapper that automatically attaches the Authorization header
 * and handles 401 responses.
 */
export function createAuthMiddleware(opts: AuthMiddlewareOptions) {
  const { getToken, tokenType = 'Bearer', onTokenExpired } = opts;

  return async function authFetch(
    input: RequestInfo | URL,
    init: RequestInit = {}
  ): Promise<Response> {
    const token = getToken();
    const headers = new Headers(init.headers);

    if (token) {
      headers.set('Authorization', `${tokenType} ${token}`);
    }

    const response = await fetch(input, { ...init, headers });

    if (response.status === 401) {
      onTokenExpired?.();
    }

    return response;
  };
}

/**
 * Inject Authorization header into an existing headers object (plain object variant).
 */
export function injectAuthHeader(
  headers: Record<string, string>,
  token: string,
  tokenType = 'Bearer'
): Record<string, string> {
  return { ...headers, Authorization: `${tokenType} ${token}` };
}
