/**
 * CSRFTokenManager Tests
 */

import { CSRFTokenManager } from '../CSRFTokenManager';

describe('CSRFTokenManager', () => {
  let csrfManager: CSRFTokenManager;

  beforeEach(() => {
    csrfManager = new CSRFTokenManager();
  });

  describe('Token Generation', () => {
    it('should generate a token', () => {
      const token = csrfManager.generateToken();
      expect(token).toBeDefined();
      expect(token.length).toBeGreaterThan(0);
    });

    it('should generate unique tokens', () => {
      const token1 = csrfManager.generateToken();
      const token2 = csrfManager.generateToken();
      expect(token1).not.toEqual(token2);
    });

    it('should generate token of correct length', () => {
      const csrfManager2 = new CSRFTokenManager({ tokenLength: 64 });
      const token = csrfManager2.generateToken();
      expect(token.length).toBe(64);
    });
  });

  describe('Token Validation', () => {
    it('should validate generated token', () => {
      const token = csrfManager.generateToken();
      expect(csrfManager.validateToken(token)).toBe(true);
    });

    it('should reject invalid token', () => {
      expect(csrfManager.validateToken('invalid-token')).toBe(false);
    });

    it('should reject empty token', () => {
      expect(csrfManager.validateToken('')).toBe(false);
    });

    it('should reject null token', () => {
      expect(csrfManager.validateToken(null as any)).toBe(false);
    });
  });

  describe('Token Expiry', () => {
    it('should clear expired tokens', () => {
      const csrfManager2 = new CSRFTokenManager({ tokenExpiryMs: 100 });
      const token = csrfManager2.generateToken();

      // Wait for token to expire
      setTimeout(() => {
        csrfManager2.clearExpiredTokens();
        expect(csrfManager2.validateToken(token)).toBe(false);
      }, 150);
    });
  });

  describe('Token Invalidation', () => {
    it('should invalidate a token', () => {
      const token = csrfManager.generateToken();
      expect(csrfManager.invalidateToken(token)).toBe(true);
      expect(csrfManager.validateToken(token)).toBe(false);
    });

    it('should handle invalidating non-existent token', () => {
      expect(csrfManager.invalidateToken('non-existent')).toBe(false);
    });
  });

  describe('Headers', () => {
    it('should return headers with token', () => {
      const headers = csrfManager.getHeaders();
      expect(headers).toBeDefined();
      expect(Object.keys(headers).length).toBeGreaterThan(0);
    });

    it('should use custom header name', () => {
      const csrfManager2 = new CSRFTokenManager({ headerName: 'X-Custom-CSRF' });
      const headers = csrfManager2.getHeaders();
      expect(headers['X-Custom-CSRF']).toBeDefined();
    });
  });

  describe('Statistics', () => {
    it('should report token statistics', () => {
      csrfManager.generateToken();
      csrfManager.generateToken();

      const stats = csrfManager.getStats();
      expect(stats.totalTokens).toBeGreaterThanOrEqual(2);
      expect(stats.validTokens).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Configuration', () => {
    it('should accept custom configuration', () => {
      const config = {
        headerName: 'X-CSRF',
        cookieName: 'csrf',
        tokenLength: 48,
        tokenExpiryMs: 30 * 60 * 1000,
      };

      const csrfManager2 = new CSRFTokenManager(config);
      const token = csrfManager2.generateToken();

      expect(token.length).toBe(48);
    });
  });

  describe('Initialize', () => {
    it('should initialize without error', () => {
      expect(() => csrfManager.initialize()).not.toThrow();
    });

    it('should generate token on init if none exists', () => {
      csrfManager.initialize();
      // Token should be generated in cookie
      expect(csrfManager.getTokenFromCookie()).toBeDefined();
    });
  });
});
