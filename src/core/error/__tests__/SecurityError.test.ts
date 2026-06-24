/**
 * SecurityError Tests
 */

import { SecurityError, SecurityErrorCode, isSecurityError } from '../SecurityError';

describe('SecurityError', () => {
  describe('Creation', () => {
    it('should create SecurityError', () => {
      const error = new SecurityError('Test error', SecurityErrorCode.AUTH_FAILED);
      expect(error).toBeInstanceOf(SecurityError);
      expect(error.message).toBe('Test error');
      expect(error.code).toBe(SecurityErrorCode.AUTH_FAILED);
    });

    it('should include context', () => {
      const context = { userId: '123', action: 'login' };
      const error = new SecurityError('Auth failed', SecurityErrorCode.AUTH_FAILED, context);
      expect(error.context).toEqual(context);
    });

    it('should include timestamp', () => {
      const error = new SecurityError('Test', SecurityErrorCode.AUTH_FAILED);
      expect(error.timestamp).toBeDefined();
      expect(typeof error.timestamp).toBe('number');
    });
  });

  describe('Error Properties', () => {
    it('should have correct name', () => {
      const error = new SecurityError('Test', SecurityErrorCode.AUTH_FAILED);
      expect(error.name).toBe('SecurityError');
    });

    it('should maintain proper prototype', () => {
      const error = new SecurityError('Test', SecurityErrorCode.AUTH_FAILED);
      expect(error instanceof Error).toBe(true);
      expect(error instanceof SecurityError).toBe(true);
    });
  });

  describe('Serialization', () => {
    it('should convert to JSON', () => {
      const context = { userId: '123' };
      const error = new SecurityError('Auth failed', SecurityErrorCode.AUTH_FAILED, context);
      const json = error.toJSON();

      expect(json.name).toBe('SecurityError');
      expect(json.message).toBe('Auth failed');
      expect(json.code).toBe(SecurityErrorCode.AUTH_FAILED);
      expect(json.context).toEqual(context);
      expect(json.timestamp).toBeDefined();
    });

    it('should be JSON stringifiable', () => {
      const error = new SecurityError('Test', SecurityErrorCode.AUTH_FAILED);
      const stringified = JSON.stringify(error);
      expect(stringified).toContain('SecurityError');
    });
  });

  describe('isSecurityError Type Guard', () => {
    it('should identify SecurityError', () => {
      const error = new SecurityError('Test', SecurityErrorCode.AUTH_FAILED);
      expect(isSecurityError(error)).toBe(true);
    });

    it('should reject regular Error', () => {
      const error = new Error('Test');
      expect(isSecurityError(error)).toBe(false);
    });

    it('should reject non-errors', () => {
      expect(isSecurityError('not an error')).toBe(false);
      expect(isSecurityError(null)).toBe(false);
      expect(isSecurityError(undefined)).toBe(false);
    });
  });

  describe('Error Codes', () => {
    it('should have all error codes defined', () => {
      expect(SecurityErrorCode.AUTH_FAILED).toBeDefined();
      expect(SecurityErrorCode.TOKEN_EXPIRED).toBeDefined();
      expect(SecurityErrorCode.PERMISSION_DENIED).toBeDefined();
      expect(SecurityErrorCode.VALIDATION_FAILED).toBeDefined();
      expect(SecurityErrorCode.CSRF_TOKEN_INVALID).toBeDefined();
      expect(SecurityErrorCode.INPUT_MALICIOUS).toBeDefined();
      expect(SecurityErrorCode.ENCRYPTION_FAILED).toBeDefined();
      expect(SecurityErrorCode.HTTP_ERROR).toBeDefined();
      expect(SecurityErrorCode.UNAUTHORIZED).toBeDefined();
      expect(SecurityErrorCode.FORBIDDEN).toBeDefined();
    });
  });
});
