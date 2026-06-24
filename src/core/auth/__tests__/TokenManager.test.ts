/**
 * TokenManager Tests
 */

import { TokenManager } from '../TokenManager';
import { AuthToken, StorageAdapter } from '../types';

describe('TokenManager', () => {
  let tokenManager: TokenManager;
  let mockStorage: StorageAdapter;
  let store: Map<string, string>;

  beforeEach(() => {
    store = new Map();
    mockStorage = {
      getItem: async (key: string) => store.get(key) ?? null,
      setItem: async (key: string, value: string) => store.set(key, value),
      removeItem: async (key: string) => store.delete(key),
    };
    tokenManager = new TokenManager(mockStorage);
  });

  describe('Token Storage', () => {
    it('should save and retrieve token', async () => {
      const token: AuthToken = {
        accessToken: 'test-token',
        expiresIn: 3600000,
        type: 'Bearer',
        issuedAt: Date.now(),
      };

      await tokenManager.saveToken(token);
      const retrieved = await tokenManager.getToken();

      expect(retrieved).toEqual(token);
    });

    it('should return null for non-existent token', async () => {
      const token = await tokenManager.getToken();
      expect(token).toBeNull();
    });

    it('should clear token', async () => {
      const token: AuthToken = {
        accessToken: 'test-token',
        expiresIn: 3600000,
        type: 'Bearer',
        issuedAt: Date.now(),
      };

      await tokenManager.saveToken(token);
      await tokenManager.clearToken();
      const retrieved = await tokenManager.getToken();

      expect(retrieved).toBeNull();
    });
  });

  describe('Token Expiry', () => {
    it('should detect expired token', () => {
      const expiredToken: AuthToken = {
        accessToken: 'test-token',
        expiresIn: 1000, // 1 second
        type: 'Bearer',
        issuedAt: Date.now() - 10000, // 10 seconds ago
      };

      expect(tokenManager.isTokenExpired(expiredToken)).toBe(true);
    });

    it('should detect valid token', () => {
      const validToken: AuthToken = {
        accessToken: 'test-token',
        expiresIn: 3600000, // 1 hour
        type: 'Bearer',
        issuedAt: Date.now(),
      };

      expect(tokenManager.isTokenExpired(validToken)).toBe(false);
    });

    it('should check if token needs refresh', () => {
      const tokenNeedingRefresh: AuthToken = {
        accessToken: 'test-token',
        expiresIn: 400000, // expires in ~6.6 minutes
        type: 'Bearer',
        issuedAt: Date.now(),
      };

      expect(tokenManager.shouldRefreshToken(tokenNeedingRefresh)).toBe(true);
    });

    it('should calculate time until expiry', () => {
      const now = Date.now();
      const token: AuthToken = {
        accessToken: 'test-token',
        expiresIn: 3600000,
        type: 'Bearer',
        issuedAt: now,
      };

      const timeLeft = tokenManager.getTimeUntilExpiry(token);
      expect(timeLeft).toBeGreaterThan(3590000); // Should be close to 1 hour
      expect(timeLeft).toBeLessThanOrEqual(3600000);
    });
  });

  describe('Token Validation', () => {
    it('should validate JWT structure', () => {
      const validJWT = 'header.payload.signature';
      expect(tokenManager.validateTokenStructure(validJWT)).toBe(true);
    });

    it('should reject invalid JWT structure', () => {
      const invalidJWT = 'invalid-token';
      expect(tokenManager.validateTokenStructure(invalidJWT)).toBe(false);
    });
  });

  describe('Token Refresh Callbacks', () => {
    it('should register and call refresh callback', () => {
      const callback = jest.fn();
      tokenManager.onTokenRefresh(callback);

      tokenManager.notifyTokenRefresh();

      expect(callback).toHaveBeenCalled();
    });

    it('should unsubscribe from refresh callbacks', () => {
      const callback = jest.fn();
      const unsubscribe = tokenManager.onTokenRefresh(callback);

      unsubscribe();
      tokenManager.notifyTokenRefresh();

      expect(callback).not.toHaveBeenCalled();
    });

    it('should handle multiple refresh callbacks', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();

      tokenManager.onTokenRefresh(callback1);
      tokenManager.onTokenRefresh(callback2);

      tokenManager.notifyTokenRefresh();

      expect(callback1).toHaveBeenCalled();
      expect(callback2).toHaveBeenCalled();
    });
  });
});
