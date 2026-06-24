/**
 * InputValidator Tests
 */

import { InputValidator } from '../InputValidator';

describe('InputValidator', () => {
  describe('Email Validation', () => {
    it('should validate correct email', () => {
      const result = InputValidator.validateEmail('test@example.com');
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject empty email', () => {
      const result = InputValidator.validateEmail('');
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject invalid email format', () => {
      const result = InputValidator.validateEmail('invalid-email');
      expect(result.isValid).toBe(false);
    });

    it('should reject email without domain', () => {
      const result = InputValidator.validateEmail('test@');
      expect(result.isValid).toBe(false);
    });

    it('should reject very long email', () => {
      const longEmail = 'a'.repeat(255) + '@example.com';
      const result = InputValidator.validateEmail(longEmail);
      expect(result.isValid).toBe(false);
    });
  });

  describe('URL Validation', () => {
    it('should validate correct URL', () => {
      const result = InputValidator.validateURL('https://example.com/page');
      expect(result.isValid).toBe(true);
    });

    it('should validate http URL', () => {
      const result = InputValidator.validateURL('http://example.com');
      expect(result.isValid).toBe(true);
    });

    it('should reject empty URL', () => {
      const result = InputValidator.validateURL('');
      expect(result.isValid).toBe(false);
    });

    it('should reject javascript: protocol', () => {
      const result = InputValidator.validateURL('javascript:alert(1)');
      expect(result.isValid).toBe(false);
    });

    it('should reject data: protocol', () => {
      const result = InputValidator.validateURL('data:text/html,<script>alert(1)</script>');
      expect(result.isValid).toBe(false);
    });
  });

  describe('Password Validation', () => {
    it('should accept strong password', () => {
      const result = InputValidator.validatePassword('StrongPass123!');
      expect(result.isValid).toBe(true);
    });

    it('should reject empty password', () => {
      const result = InputValidator.validatePassword('');
      expect(result.isValid).toBe(false);
    });

    it('should reject short password', () => {
      const result = InputValidator.validatePassword('Short1!');
      expect(result.isValid).toBe(false);
    });

    it('should require uppercase', () => {
      const result = InputValidator.validatePassword('lowercase123!');
      expect(result.isValid).toBe(false);
    });

    it('should require lowercase', () => {
      const result = InputValidator.validatePassword('UPPERCASE123!');
      expect(result.isValid).toBe(false);
    });

    it('should require digit', () => {
      const result = InputValidator.validatePassword('NoDigitPass!');
      expect(result.isValid).toBe(false);
    });

    it('should require special character', () => {
      const result = InputValidator.validatePassword('NoSpecialChar123');
      expect(result.isValid).toBe(false);
    });

    it('should reject very long password', () => {
      const longPass = 'Strong' + 'A'.repeat(130) + '1!';
      const result = InputValidator.validatePassword(longPass);
      expect(result.isValid).toBe(false);
    });
  });

  describe('Credit Card Validation', () => {
    it('should validate valid credit card', () => {
      const result = InputValidator.validateCreditCard('4532015112830366');
      expect(result.isValid).toBe(true);
    });

    it('should accept formatted credit card', () => {
      const result = InputValidator.validateCreditCard('4532-0151-1283-0366');
      expect(result.isValid).toBe(true);
    });

    it('should reject empty card', () => {
      const result = InputValidator.validateCreditCard('');
      expect(result.isValid).toBe(false);
    });

    it('should reject invalid card length', () => {
      const result = InputValidator.validateCreditCard('123456789');
      expect(result.isValid).toBe(false);
    });

    it('should reject non-numeric characters', () => {
      const result = InputValidator.validateCreditCard('abcd-efgh-ijkl-mnop');
      expect(result.isValid).toBe(false);
    });
  });

  describe('Phone Validation', () => {
    it('should validate phone with digits', () => {
      const result = InputValidator.validatePhone('1234567890');
      expect(result.isValid).toBe(true);
    });

    it('should validate formatted phone', () => {
      const result = InputValidator.validatePhone('+1 (123) 456-7890');
      expect(result.isValid).toBe(true);
    });

    it('should reject empty phone', () => {
      const result = InputValidator.validatePhone('');
      expect(result.isValid).toBe(false);
    });

    it('should reject phone with too few digits', () => {
      const result = InputValidator.validatePhone('12345');
      expect(result.isValid).toBe(false);
    });
  });

  describe('Length Validation', () => {
    it('should validate text within bounds', () => {
      const result = InputValidator.validateLength('hello', 3, 10);
      expect(result.isValid).toBe(true);
    });

    it('should reject text below minimum', () => {
      const result = InputValidator.validateLength('hi', 3, 10);
      expect(result.isValid).toBe(false);
    });

    it('should reject text above maximum', () => {
      const result = InputValidator.validateLength('hello world!', 3, 10);
      expect(result.isValid).toBe(false);
    });

    it('should reject empty text', () => {
      const result = InputValidator.validateLength('', 1, 10);
      expect(result.isValid).toBe(false);
    });
  });

  describe('Pattern Validation', () => {
    it('should validate against regex', () => {
      const result = InputValidator.validatePattern('abc123', /^[a-z0-9]+$/);
      expect(result.isValid).toBe(true);
    });

    it('should reject non-matching pattern', () => {
      const result = InputValidator.validatePattern('ABC', /^[a-z]+$/);
      expect(result.isValid).toBe(false);
    });

    it('should use custom error message', () => {
      const result = InputValidator.validatePattern('ABC', /^[a-z]+$/, 'Must be lowercase');
      expect(result.errors[0]).toBe('Must be lowercase');
    });
  });

  describe('Integer Validation', () => {
    it('should validate positive integer', () => {
      const result = InputValidator.validateInteger('123');
      expect(result.isValid).toBe(true);
    });

    it('should validate negative integer', () => {
      const result = InputValidator.validateInteger('-123');
      expect(result.isValid).toBe(true);
    });

    it('should reject non-integer', () => {
      const result = InputValidator.validateInteger('12.34');
      expect(result.isValid).toBe(false);
    });

    it('should validate min constraint', () => {
      const result = InputValidator.validateInteger('5', 10);
      expect(result.isValid).toBe(false);
    });

    it('should validate max constraint', () => {
      const result = InputValidator.validateInteger('15', 5, 10);
      expect(result.isValid).toBe(false);
    });
  });

  describe('Float Validation', () => {
    it('should validate float', () => {
      const result = InputValidator.validateFloat('12.34');
      expect(result.isValid).toBe(true);
    });

    it('should validate integer as float', () => {
      const result = InputValidator.validateFloat('123');
      expect(result.isValid).toBe(true);
    });

    it('should validate negative float', () => {
      const result = InputValidator.validateFloat('-12.34');
      expect(result.isValid).toBe(true);
    });

    it('should reject non-numeric', () => {
      const result = InputValidator.validateFloat('abc');
      expect(result.isValid).toBe(false);
    });

    it('should validate min/max', () => {
      const result = InputValidator.validateFloat('15.5', 10, 20);
      expect(result.isValid).toBe(true);
    });
  });

  describe('Username Validation', () => {
    it('should validate valid username', () => {
      const result = InputValidator.validateUsername('user_123');
      expect(result.isValid).toBe(true);
    });

    it('should allow hyphens', () => {
      const result = InputValidator.validateUsername('user-name');
      expect(result.isValid).toBe(true);
    });

    it('should reject too short', () => {
      const result = InputValidator.validateUsername('ab');
      expect(result.isValid).toBe(false);
    });

    it('should reject special characters', () => {
      const result = InputValidator.validateUsername('user@name');
      expect(result.isValid).toBe(false);
    });

    it('should reject too long', () => {
      const result = InputValidator.validateUsername('a'.repeat(33));
      expect(result.isValid).toBe(false);
    });
  });

  describe('Rule-based Validation', () => {
    it('should validate with multiple rules', () => {
      const rules = [
        { validate: (v: string) => v.length > 5, message: 'Too short' },
        { validate: (v: string) => /[A-Z]/.test(v), message: 'No uppercase' },
      ];

      const result = InputValidator.validateWithRules('Hello123', rules);
      expect(result.isValid).toBe(true);
    });

    it('should collect all errors', () => {
      const rules = [
        { validate: () => false, message: 'Error 1' },
        { validate: () => false, message: 'Error 2' },
      ];

      const result = InputValidator.validateWithRules('test', rules);
      expect(result.errors).toHaveLength(2);
    });
  });
});
