import { TokenManager } from '../../utils/tokenManager';
import { AuthToken } from '../../types';

const makeToken = (overrides: Partial<AuthToken> = {}): AuthToken => ({
  accessToken: 'test.access.token',
  expiresIn: 3_600_000, // 1 hour
  issuedAt: Date.now(),
  type: 'Bearer',
  ...overrides,
});

beforeEach(() => {
  sessionStorage.clear();
});

describe('TokenManager', () => {
  describe('saveToken / getToken', () => {
    it('saves and retrieves a token', () => {
      const token = makeToken();
      TokenManager.saveToken(token);
      expect(TokenManager.getToken()).toEqual(token);
    });

    it('returns null when no token stored', () => {
      expect(TokenManager.getToken()).toBeNull();
    });
  });

  describe('clearToken', () => {
    it('removes stored token', () => {
      TokenManager.saveToken(makeToken());
      TokenManager.clearToken();
      expect(TokenManager.getToken()).toBeNull();
    });
  });

  describe('isTokenExpired', () => {
    it('returns false for a fresh token', () => {
      expect(TokenManager.isTokenExpired(makeToken())).toBe(false);
    });

    it('returns true for an expired token', () => {
      const expired = makeToken({ issuedAt: Date.now() - 7_200_000 }); // issued 2 hours ago, expires in 1h
      expect(TokenManager.isTokenExpired(expired)).toBe(true);
    });
  });

  describe('shouldRefreshToken', () => {
    it('returns false when plenty of time remains', () => {
      expect(TokenManager.shouldRefreshToken(makeToken())).toBe(false);
    });

    it('returns true when within refresh threshold', () => {
      const nearExpiry = makeToken({
        issuedAt: Date.now() - 3_500_000, // expires in ~100 seconds
      });
      expect(TokenManager.shouldRefreshToken(nearExpiry)).toBe(true);
    });
  });

  describe('validateTokenStructure', () => {
    it('accepts a three-part base64url token', () => {
      const token = 'aGVhZA.cGF5bG9hZA.c2ln';
      expect(TokenManager.validateTokenStructure(token)).toBe(true);
    });

    it('rejects a single-part string', () => {
      expect(TokenManager.validateTokenStructure('notavalidtoken')).toBe(false);
    });

    it('rejects empty string', () => {
      expect(TokenManager.validateTokenStructure('')).toBe(false);
    });
  });

  describe('decodeToken', () => {
    it('decodes a real JWT payload', () => {
      // header.payload.sig — payload is base64url({"sub":"1"})
      const payload = btoa(JSON.stringify({ sub: '1' }))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      const token = `header.${payload}.sig`;
      const decoded = TokenManager.decodeToken(token);
      expect(decoded).toEqual({ sub: '1' });
    });

    it('returns null for malformed token', () => {
      expect(TokenManager.decodeToken('not.valid')).toBeNull();
    });
  });
});
