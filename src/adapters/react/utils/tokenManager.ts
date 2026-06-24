import { AuthToken } from '../types';

const STORAGE_KEY = 'webshield_auth_token';

function getStorage(): Storage | null {
  try {
    return typeof sessionStorage !== 'undefined' ? sessionStorage : null;
  } catch {
    return null;
  }
}

export class TokenManager {
  static readonly REFRESH_THRESHOLD_MS = 5 * 60 * 1000;

  static saveToken(token: AuthToken): void {
    try {
      getStorage()?.setItem(STORAGE_KEY, JSON.stringify(token));
    } catch {
      // Storage unavailable — token won't persist across page loads
    }
  }

  static getToken(): AuthToken | null {
    try {
      const raw = getStorage()?.getItem(STORAGE_KEY);
      return raw ? (JSON.parse(raw) as AuthToken) : null;
    } catch {
      return null;
    }
  }

  static clearToken(): void {
    try {
      getStorage()?.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
  }

  static isTokenExpired(token: AuthToken): boolean {
    return Date.now() >= token.issuedAt + token.expiresIn;
  }

  static shouldRefreshToken(token: AuthToken): boolean {
    const timeLeft = token.issuedAt + token.expiresIn - Date.now();
    return timeLeft > 0 && timeLeft < this.REFRESH_THRESHOLD_MS;
  }

  /**
   * Validate that a string looks like a JWT (three base64url-encoded parts).
   */
  static validateTokenStructure(token: string): boolean {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    return parts.every((part) => /^[A-Za-z0-9_-]+={0,2}$/.test(part));
  }

  /**
   * Decode the JWT payload WITHOUT verifying the signature.
   * Always verify tokens server-side.
   */
  static decodeToken(token: string): Record<string, unknown> | null {
    try {
      const payload = token.split('.')[1];
      // Normalize base64url → base64
      const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
      const json = atob(base64);
      return JSON.parse(json) as Record<string, unknown>;
    } catch {
      return null;
    }
  }
}
