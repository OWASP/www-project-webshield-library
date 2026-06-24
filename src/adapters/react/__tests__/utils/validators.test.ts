import { Validators } from '../../utils/validators';

describe('Validators', () => {
  describe('validateEmail', () => {
    it('accepts valid email', () => {
      expect(Validators.validateEmail('user@example.com')).toBe(true);
    });

    it('accepts email with subdomain', () => {
      expect(Validators.validateEmail('user@mail.example.co.uk')).toBe(true);
    });

    it('rejects missing @', () => {
      expect(Validators.validateEmail('userexample.com')).toBe(false);
    });

    it('rejects empty string', () => {
      expect(Validators.validateEmail('')).toBe(false);
    });

    it('rejects email longer than 254 chars', () => {
      const long = 'a'.repeat(250) + '@b.co';
      expect(Validators.validateEmail(long)).toBe(false);
    });
  });

  describe('validateURL', () => {
    it('accepts https URL', () => {
      expect(Validators.validateURL('https://example.com/path')).toBe(true);
    });

    it('accepts http URL', () => {
      expect(Validators.validateURL('http://example.com')).toBe(true);
    });

    it('rejects javascript: URL', () => {
      expect(Validators.validateURL('javascript:alert(1)')).toBe(false);
    });

    it('rejects plain text', () => {
      expect(Validators.validateURL('not a url')).toBe(false);
    });
  });

  describe('validatePassword', () => {
    it('accepts strong password', () => {
      expect(Validators.validatePassword('Secure@Pass1').isValid).toBe(true);
    });

    it('rejects short password', () => {
      const r = Validators.validatePassword('Ab1@');
      expect(r.isValid).toBe(false);
      expect(r.feedback.some((m) => m.includes('8 characters'))).toBe(true);
    });

    it('rejects missing uppercase', () => {
      const r = Validators.validatePassword('secure@pass1');
      expect(r.isValid).toBe(false);
    });

    it('rejects missing special char', () => {
      const r = Validators.validatePassword('SecurePass1');
      expect(r.isValid).toBe(false);
    });

    it('rejects password over 128 chars', () => {
      const r = Validators.validatePassword('A@1' + 'a'.repeat(130));
      expect(r.isValid).toBe(false);
    });
  });

  describe('validateCreditCard', () => {
    it('accepts valid Visa test number', () => {
      expect(Validators.validateCreditCard('4532015112830366')).toBe(true);
    });

    it('accepts number with spaces', () => {
      expect(Validators.validateCreditCard('4532 0151 1283 0366')).toBe(true);
    });

    it('rejects clearly invalid number', () => {
      expect(Validators.validateCreditCard('1234567890123456')).toBe(false);
    });

    it('rejects too-short number', () => {
      expect(Validators.validateCreditCard('123456')).toBe(false);
    });
  });

  describe('validatePhone', () => {
    it('accepts US format', () => {
      expect(Validators.validatePhone('(555)123-4567')).toBe(true);
    });

    it('accepts international format', () => {
      expect(Validators.validatePhone('+15551234567')).toBe(true);
    });

    it('rejects letters', () => {
      expect(Validators.validatePhone('abc-defg-hijk')).toBe(false);
    });
  });

  describe('validateLength', () => {
    it('accepts value within range', () => {
      expect(Validators.validateLength('hello', 3, 10)).toBe(true);
    });

    it('rejects value below min', () => {
      expect(Validators.validateLength('hi', 3, 10)).toBe(false);
    });

    it('rejects value above max', () => {
      expect(Validators.validateLength('hello world', 3, 5)).toBe(false);
    });
  });

  describe('validateUsername', () => {
    it('accepts valid username', () => {
      expect(Validators.validateUsername('user_name-01')).toBe(true);
    });

    it('rejects username with spaces', () => {
      expect(Validators.validateUsername('user name')).toBe(false);
    });

    it('rejects too-short username', () => {
      expect(Validators.validateUsername('ab')).toBe(false);
    });
  });
});
