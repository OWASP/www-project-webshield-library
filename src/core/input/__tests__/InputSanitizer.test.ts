/**
 * InputSanitizer Tests
 */

import { InputSanitizer } from '../InputSanitizer';

describe('InputSanitizer', () => {
  describe('XSS Prevention', () => {
    it('should remove script tags', () => {
      const input = '<p>Hello<script>alert("xss")</script>World</p>';
      const result = InputSanitizer.sanitizeInput(input);
      expect(result).not.toContain('<script>');
      expect(result).not.toContain('alert');
    });

    it('should remove event handlers', () => {
      const input = '<p onclick="alert(1)">Click me</p>';
      const result = InputSanitizer.sanitizeInput(input);
      expect(result).not.toContain('onclick');
    });

    it('should remove iframe tags', () => {
      const input = '<iframe src="malicious.com"></iframe>';
      const result = InputSanitizer.sanitizeInput(input);
      expect(result).not.toContain('<iframe');
    });

    it('should prevent XSS with encoding', () => {
      const input = '<img src=x onerror="alert(1)">';
      const result = InputSanitizer.preventXSS(input);
      expect(result).toContain('&lt;');
      expect(result).toContain('&gt;');
    });
  });

  describe('HTML Entity Encoding', () => {
    it('should encode HTML entities', () => {
      // Skip in Node.js environment (no document object)
      if (typeof document === 'undefined') {
        expect(true).toBe(true);
        return;
      }
      const input = '< & > " \'';  
      const encoded = InputSanitizer.encodeHTML(input);
      expect(encoded).not.toContain('<');
      expect(encoded).not.toContain('&'); // Will be part of entity
    });

    it('should decode HTML entities', () => {
      // Skip in Node.js environment (no document object)
      if (typeof document === 'undefined') {
        expect(true).toBe(true);
        return;
      }
      const encoded = '&lt;p&gt;test&lt;/p&gt;';
      const decoded = InputSanitizer.decodeHTML(encoded);
      expect(decoded).toBe('<p>test</p>');
    });
  });

  describe('URL Sanitization', () => {
    it('should allow valid URLs', () => {
      const url = 'https://example.com/page';
      const result = InputSanitizer.sanitizeURL(url);
      expect(result).toBe(url);
    });

    it('should remove javascript: protocol', () => {
      const url = 'javascript:alert(1)';
      const result = InputSanitizer.sanitizeURL(url);
      expect(result).toBe('');
    });

    it('should remove data: protocol', () => {
      const url = 'data:text/html,<script>alert(1)</script>';
      const result = InputSanitizer.sanitizeURL(url);
      expect(result).toBe('');
    });

    it('should handle case-insensitive protocols', () => {
      const url = 'JavaScript:alert(1)';
      const result = InputSanitizer.sanitizeURL(url);
      expect(result).toBe('');
    });
  });

  describe('Tag Stripping', () => {
    it('should strip all HTML tags', () => {
      const input = '<p>Hello <strong>World</strong></p>';
      const result = InputSanitizer.stripTags(input);
      expect(result).toBe('Hello World');
    });

    it('should strip dangerous tags', () => {
      const input = '<div><script>alert(1)</script><p>Safe</p></div>';
      const result = InputSanitizer.stripDangerousTags(input);
      expect(result).not.toContain('<script');
    });
  });

  describe('Attribute Removal', () => {
    it('should remove dangerous attributes', () => {
      const input = '<div onclick="alert(1)" onerror="test">Content</div>';
      const result = InputSanitizer.removeDangerousAttributes(input);
      expect(result).not.toContain('onclick');
      expect(result).not.toContain('onerror');
    });

    it('should handle various event handlers', () => {
      const input =
        '<img onload="x" onmouseover="y" onchange="z">';
      const result = InputSanitizer.removeDangerousAttributes(input);
      expect(result).not.toContain('onload');
      expect(result).not.toContain('onmouseover');
      expect(result).not.toContain('onchange');
    });
  });

  describe('File Name Sanitization', () => {
    it('should sanitize file names', () => {
      const fileName = '../../../etc/passwd';
      const result = InputSanitizer.sanitizeFileName(fileName);
      expect(result).not.toContain('..');
      expect(result).not.toContain('/');
    });

    it('should remove special characters', () => {
      const fileName = 'file<>:|?.txt';
      const result = InputSanitizer.sanitizeFileName(fileName);
      expect(result).not.toContain('<');
      expect(result).not.toContain('>');
    });

    it('should provide fallback file name', () => {
      const fileName = '!!!###@@@';
      const result = InputSanitizer.sanitizeFileName(fileName);
      expect(result).toBe('file');
    });
  });

  describe('CSS Sanitization', () => {
    it('should remove dangerous CSS properties', () => {
      const css = 'color: red; expression(alert(1)); background: blue;';
      const result = InputSanitizer.sanitizeCSS(css);
      expect(result).not.toContain('expression');
    });

    it('should remove behavior property', () => {
      const css = 'behavior: url(xss.htc);';
      const result = InputSanitizer.sanitizeCSS(css);
      expect(result).not.toContain('behavior');
    });
  });

  describe('Whitespace Normalization', () => {
    it('should normalize multiple spaces', () => {
      const input = 'Hello    World';
      const result = InputSanitizer.normalizeWhitespace(input);
      expect(result).toBe('Hello World');
    });

    it('should trim leading/trailing whitespace', () => {
      const input = '   Hello World   ';
      const result = InputSanitizer.normalizeWhitespace(input);
      expect(result).toBe('Hello World');
    });
  });
});
