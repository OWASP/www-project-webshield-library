/**
 * CSRF middleware utilities.
 * Provides token generation, cookie reading, and fetch-level injection.
 */

const COOKIE_NAME = '_webshield_csrf';
const HEADER_NAME = 'X-CSRF-Token';
const MUTATING_METHODS = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);

export class CSRFMiddleware {
  /**
   * Generate a cryptographically random hex token.
   */
  static generateToken(byteLength = 32): string {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Read the CSRF token from document.cookie.
   */
  static getToken(): string | null {
    if (typeof document === 'undefined') return null;
    const match = document.cookie
      .split(';')
      .map((c) => c.trim())
      .find((c) => c.startsWith(`${COOKIE_NAME}=`));
    return match ? decodeURIComponent(match.split('=')[1]) : null;
  }

  /**
   * Initialize: read or generate the CSRF cookie on first load.
   */
  static initialize(): string {
    let token = this.getToken();
    if (!token) {
      token = this.generateToken();
      if (typeof document !== 'undefined') {
        document.cookie = `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; SameSite=Strict`;
      }
    }
    return token;
  }

  /**
   * Inject CSRF token into a headers plain object.
   */
  static injectToken(
    headers: Record<string, string>
  ): Record<string, string> {
    const token = this.getToken();
    if (!token) return headers;
    return { ...headers, [HEADER_NAME]: token };
  }

  /**
   * Install a global fetch monkey-patch that injects the CSRF header for
   * all state-mutating requests.  Returns a cleanup function.
   */
  static createFetchInterceptor(): () => void {
    if (typeof window === 'undefined') return () => {/* noop */};

    const original = window.fetch.bind(window);

    window.fetch = function csrfFetch(input, init = {}) {
      const method = ((init.method ?? 'GET') as string).toUpperCase();
      if (MUTATING_METHODS.has(method)) {
        const token = CSRFMiddleware.getToken();
        if (token) {
          const headers = new Headers(init.headers);
          if (!headers.has(HEADER_NAME)) headers.set(HEADER_NAME, token);
          init = { ...init, headers };
        }
      }
      return original(input, init);
    };

    return () => {
      window.fetch = original;
    };
  }
}
