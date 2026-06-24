/**
 * TokenManager - Manages JWT token lifecycle
 * Handles storage, validation, expiry checking, and refresh logic
 */

import { AuthToken, StorageAdapter } from './types';

export class TokenManager {
  private static readonly STORAGE_KEY = '@owasp/auth_token';
  private static readonly REFRESH_THRESHOLD = 5 * 60 * 1000; // 5 minutes
  private storageAdapter: StorageAdapter;
  private tokenRefreshCallbacks: Set<() => void> = new Set();

  /**
   * Initialize TokenManager with storage adapter
   */
  constructor(storageAdapter: StorageAdapter) {
    this.storageAdapter = storageAdapter;
  }

  /**
   * Save token to storage
   */
  async saveToken(token: AuthToken): Promise<void> {
    try {
      const tokenString = JSON.stringify(token);
      await this.storageAdapter.setItem(TokenManager.STORAGE_KEY, tokenString);
    } catch (error) {
      console.error('Error saving token:', error);
      throw new Error('Failed to save authentication token');
    }
  }

  /**
   * Retrieve token from storage
   */
  async getToken(): Promise<AuthToken | null> {
    try {
      const tokenString = await this.storageAdapter.getItem(TokenManager.STORAGE_KEY);
      if (!tokenString) {
        return null;
      }
      return JSON.parse(tokenString) as AuthToken;
    } catch (error) {
      console.error('Error retrieving token:', error);
      return null;
    }
  }

  /**
   * Check if token is expired
   */
  isTokenExpired(token: AuthToken): boolean {
    if (!token || !token.expiresIn) {
      return true;
    }

    const now = Date.now();
    const expiryTime = token.issuedAt + token.expiresIn;
    return now >= expiryTime;
  }

  /**
   * Check if token needs refresh (approaching expiry)
   */
  shouldRefreshToken(token: AuthToken): boolean {
    if (!token || !token.expiresIn) {
      return false;
    }

    const now = Date.now();
    const expiryTime = token.issuedAt + token.expiresIn;
    const timeUntilExpiry = expiryTime - now;

    return (
      timeUntilExpiry < TokenManager.REFRESH_THRESHOLD && timeUntilExpiry > 0
    );
  }

  /**
   * Clear token from storage
   */
  async clearToken(): Promise<void> {
    try {
      await this.storageAdapter.removeItem(TokenManager.STORAGE_KEY);
    } catch (error) {
      console.error('Error clearing token:', error);
    }
  }

  /**
   * Validate JWT token structure (basic check for format)
   */
  validateTokenStructure(token: string): boolean {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return false;
      }

      // Check if each part is valid base64
      return parts.every((part) => this.isValidBase64(part));
    } catch {
      return false;
    }
  }

  /**
   * Decode JWT payload (without validation)
   */
  decodeToken(token: string): Record<string, any> | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return null;
      }

      const decodedPayload = atob(parts[1]);
      return JSON.parse(decodedPayload);
    } catch {
      return null;
    }
  }

  /**
   * Get time remaining until token expiry
   */
  getTimeUntilExpiry(token: AuthToken): number {
    const expiryTime = token.issuedAt + token.expiresIn;
    const now = Date.now();
    const timeUntilExpiry = expiryTime - now;
    return Math.max(0, timeUntilExpiry);
  }

  /**
   * Register callback for token refresh events
   */
  onTokenRefresh(callback: () => void): () => void {
    this.tokenRefreshCallbacks.add(callback);
    // Return unsubscribe function
    return () => this.tokenRefreshCallbacks.delete(callback);
  }

  /**
   * Notify all listeners of token refresh
   */
  notifyTokenRefresh(): void {
    this.tokenRefreshCallbacks.forEach((callback) => callback());
  }

  /**
   * Validate base64 string
   */
  private isValidBase64(str: string): boolean {
    try {
      return btoa(atob(str)) === str;
    } catch {
      return false;
    }
  }
}
