import { Sanitizer } from '../../utils/sanitizer';

describe('Sanitizer', () => {
  describe('sanitizeInput', () => {
    it('removes script tags', () => {
      const result = Sanitizer.sanitizeInput('<script>alert(1)</script>');
      expect(result).not.toContain('<script');
    });

    it('removes inline event handlers', () => {
      const result = Sanitizer.sanitizeInput('<img onerror="evil()">');
      expect(result).not.toMatch(/on\w+/i);
    });

    it('returns empty string for empty input', () => {
      expect(Sanitizer.sanitizeInput('')).toBe('');
    });

    it('preserves safe text content', () => {
      const safe = 'Hello, world!';
      expect(Sanitizer.sanitizeInput(safe)).toBe(safe);
    });

    it('trims whitespace', () => {
      expect(Sanitizer.sanitizeInput('  hello  ')).toBe('hello');
    });
  });

  describe('encodeHTML', () => {
    it('encodes ampersand', () => {
      expect(Sanitizer.encodeHTML('a & b')).toBe('a &amp; b');
    });

    it('encodes angle brackets', () => {
      expect(Sanitizer.encodeHTML('<div>')).toBe('&lt;div&gt;');
    });

    it('encodes quotes', () => {
      expect(Sanitizer.encodeHTML('"hello"')).toBe('&quot;hello&quot;');
    });

    it('encodes single quotes', () => {
      expect(Sanitizer.encodeHTML("it's")).toBe("it&#39;s");
    });

    it('encodes forward slashes', () => {
      expect(Sanitizer.encodeHTML('a/b')).toBe('a&#x2F;b');
    });
  });

  describe('stripTags', () => {
    it('strips all HTML tags', () => {
      expect(Sanitizer.stripTags('<p>Hello <b>world</b></p>')).toBe(
        'Hello world'
      );
    });

    it('returns plain text unchanged', () => {
      expect(Sanitizer.stripTags('plain text')).toBe('plain text');
    });
  });

  describe('sanitizeURL', () => {
    it('allows https URLs', () => {
      expect(Sanitizer.sanitizeURL('https://example.com')).toBe(
        'https://example.com'
      );
    });

    it('allows http URLs', () => {
      expect(Sanitizer.sanitizeURL('http://example.com')).toBe(
        'http://example.com'
      );
    });

    it('blocks javascript: protocol', () => {
      expect(Sanitizer.sanitizeURL('javascript:alert(1)')).toBe('');
    });

    it('blocks data: protocol', () => {
      expect(Sanitizer.sanitizeURL('data:text/html,<h1>xss</h1>')).toBe('');
    });

    it('returns empty string for empty input', () => {
      expect(Sanitizer.sanitizeURL('')).toBe('');
    });
  });
});
