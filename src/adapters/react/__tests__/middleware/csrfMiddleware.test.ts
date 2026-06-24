import { CSRFMiddleware } from '../../middleware/csrfMiddleware';

beforeEach(() => {
  // Clear the CSRF cookie between tests
  document.cookie = '_webshield_csrf=; Max-Age=0; Path=/';
  // Always provide a window.fetch mock so createFetchInterceptor can bind to it
  window.fetch = jest.fn().mockResolvedValue(new Response('{}', { status: 200 }));
});

describe('CSRFMiddleware', () => {
  describe('generateToken', () => {
    it('returns a 64-char hex string (32 bytes)', () => {
      const token = CSRFMiddleware.generateToken();
      expect(token).toHaveLength(64);
      expect(/^[0-9a-f]+$/.test(token)).toBe(true);
    });

    it('returns unique tokens on each call', () => {
      const a = CSRFMiddleware.generateToken();
      const b = CSRFMiddleware.generateToken();
      expect(a).not.toBe(b);
    });
  });

  describe('initialize', () => {
    it('creates a cookie and returns the token', () => {
      const token = CSRFMiddleware.initialize();
      expect(token).toBeTruthy();
      expect(document.cookie).toContain('_webshield_csrf');
    });

    it('returns the same token on repeated calls', () => {
      const first = CSRFMiddleware.initialize();
      const second = CSRFMiddleware.initialize();
      expect(first).toBe(second);
    });
  });

  describe('getToken', () => {
    it('returns null when cookie is absent', () => {
      expect(CSRFMiddleware.getToken()).toBeNull();
    });

    it('reads the cookie value', () => {
      CSRFMiddleware.initialize();
      const token = CSRFMiddleware.getToken();
      expect(token).toBeTruthy();
    });
  });

  describe('injectToken', () => {
    it('adds X-CSRF-Token header when cookie exists', () => {
      CSRFMiddleware.initialize();
      const headers = CSRFMiddleware.injectToken({});
      expect(headers['X-CSRF-Token']).toBeTruthy();
    });

    it('returns headers unchanged when no cookie exists', () => {
      const headers = CSRFMiddleware.injectToken({ 'Content-Type': 'application/json' });
      expect(headers['X-CSRF-Token']).toBeUndefined();
      expect(headers['Content-Type']).toBe('application/json');
    });
  });

  describe('createFetchInterceptor', () => {
    it('returns a cleanup function', () => {
      const restore = CSRFMiddleware.createFetchInterceptor();
      expect(typeof restore).toBe('function');
      restore();
    });
  });
});
