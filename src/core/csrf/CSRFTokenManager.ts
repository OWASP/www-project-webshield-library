/**
 * CSRFTokenManager - Manages CSRF tokens for protection against Cross-Site Request Forgery
 * Generates, stores, and validates CSRF tokens
 */

import { CSRFToken, CSRFConfig } from './types';

export class CSRFTokenManager {
  private static readonly DEFAULT_TOKEN_LENGTH = 32;
  private static readonly DEFAULT_EXPIRY_MS = 60 * 60 * 1000; // 1 hour
  private static readonly HEADER_NAME = 'X-CSRF-Token';
  private static readonly COOKIE_NAME = '_csrf_token';

  private tokens: Map<string, CSRFToken> = new Map();
  private config: CSRFConfig;

  constructor(config: CSRFConfig = {}) {
    this.config = {
      headerName: CSRFTokenManager.HEADER_NAME,
      cookieName: CSRFTokenManager.COOKIE_NAME,
      tokenLength: CSRFTokenManager.DEFAULT_TOKEN_LENGTH,
      tokenExpiryMs: CSRFTokenManager.DEFAULT_EXPIRY_MS,
      ...config,
    };
  }

  /**
   * Generate a new CSRF token
   */
  generateToken(): string {
    const token = this.generateRandomToken(
      this.config.tokenLength || CSRFTokenManager.DEFAULT_TOKEN_LENGTH
    );

    const csrfToken: CSRFToken = {
      token,
      createdAt: Date.now(),
      expiresAt:
        Date.now() +
        (this.config.tokenExpiryMs || CSRFTokenManager.DEFAULT_EXPIRY_MS),
    };

    this.tokens.set(token, csrfToken);
    this.storeTokenInCookie(token);

    return token;
  }

  /**
   * Get existing token from cookie
   */
  getTokenFromCookie(): string | null {
    if (typeof document === 'undefined') {
      return null;
    }

    const cookieName = (this.config.cookieName || CSRFTokenManager.COOKIE_NAME) + '=';
    const decodedCookie = decodeURIComponent(document.cookie);
    const cookieArray = decodedCookie.split(';');

    for (const cookie of cookieArray) {
      const trimmed = cookie.trim();
      if (trimmed.startsWith(cookieName)) {
        return trimmed.substring(cookieName.length);
      }
    }

    return null;
  }

  /**
   * Store token in cookie
   */
  private storeTokenInCookie(token: string): void {
    if (typeof document === 'undefined') {
      return;
    }

    const expiryDate = new Date();
    expiryDate.setTime(
      expiryDate.getTime() +
        (this.config.tokenExpiryMs || CSRFTokenManager.DEFAULT_EXPIRY_MS)
    );

    document.cookie = `${this.config.cookieName || CSRFTokenManager.COOKIE_NAME}=${token};expires=${expiryDate.toUTCString()};path=/;SameSite=Strict;Secure`;
  }

  /**
   * Validate CSRF token
   */
  validateToken(token: string): boolean {
    if (!token) {
      return false;
    }

    const csrfToken = this.tokens.get(token);
    if (!csrfToken) {
      return false;
    }

    // Check if token has expired
    if (csrfToken.expiresAt < Date.now()) {
      this.tokens.delete(token);
      return false;
    }

    return true;
  }

  /**
   * Get CSRF headers for requests
   */
  getHeaders(): Record<string, string> {
    const token = this.getTokenFromCookie() || this.generateToken();
    return {
      [this.config.headerName || CSRFTokenManager.HEADER_NAME]: token,
    };
  }

  /**
   * Clear all expired tokens
   */
  clearExpiredTokens(): void {
    const now = Date.now();

    for (const [token, csrfToken] of this.tokens.entries()) {
      if (csrfToken.expiresAt < now) {
        this.tokens.delete(token);
      }
    }
  }

  /**
   * Invalidate a token
   */
  invalidateToken(token: string): boolean {
    return this.tokens.delete(token);
  }

  /**
   * Initialize CSRF protection
   */
  initialize(): void {
    // Generate initial token
    const existingToken = this.getTokenFromCookie();
    if (!existingToken) {
      this.generateToken();
    }

    // Clear expired tokens periodically
    setInterval(() => {
      this.clearExpiredTokens();
    }, 60 * 1000); // Every minute
  }

  /**
   * Generate random token
   */
  private generateRandomToken(length: number): string {
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';

    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      // Use Web Crypto API if available
      const randomValues = crypto.getRandomValues(new Uint8Array(length));
      for (let i = 0; i < length; i++) {
        token += chars[randomValues[i] % chars.length];
      }
    } else {
      // Fallback to Math.random()
      for (let i = 0; i < length; i++) {
        token += chars[Math.floor(Math.random() * chars.length)];
      }
    }

    return token;
  }

  /**
   * Get token statistics
   */
  getStats() {
    return {
      totalTokens: this.tokens.size,
      validTokens: Array.from(this.tokens.values()).filter(
        (t) => t.expiresAt >= Date.now()
      ).length,
    };
  }
}
