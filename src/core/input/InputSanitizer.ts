/**
 * InputSanitizer - Prevents XSS and injection attacks
 * Sanitizes user input by removing malicious scripts and HTML
 */

import { SanitizationOptions } from './types';

export class InputSanitizer {
  private static readonly DEFAULT_ALLOWED_TAGS = [
    'p',
    'br',
    'strong',
    'em',
    'u',
    'a',
    'ul',
    'ol',
    'li',
    'code',
    'pre',
    'blockquote',
  ];

  private static readonly DANGEROUS_TAGS = [
    'script',
    'iframe',
    'object',
    'embed',
    'form',
  ];

  private static readonly DANGEROUS_ATTRIBUTES = [
    'onerror',
    'onload',
    'onclick',
    'onmouseover',
    'onmouseenter',
    'onchange',
    'onsubmit',
  ];

  /**
   * Sanitize user input to prevent XSS
   */
  static sanitizeInput(input: string, options: SanitizationOptions = {}): string {
    if (!input) {
      return '';
    }

    let sanitized = input;

    // Strip dangerous tags
    sanitized = this.stripDangerousTags(sanitized);

    // Remove dangerous event handlers
    sanitized = this.removeDangerousAttributes(sanitized);

    // Remove scripts
    if (options.stripScripts !== false) {
      sanitized = this.removeScripts(sanitized);
    }

    // Normalize whitespace
    if (options.normalizeWhitespace) {
      sanitized = this.normalizeWhitespace(sanitized);
    }

    // Encode HTML entities
    if (options.encodeHTML) {
      sanitized = this.encodeHTML(sanitized);
    }

    return sanitized;
  }

  /**
   * Encode HTML entities to prevent XSS
   */
  static encodeHTML(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Decode HTML entities
   */
  static decodeHTML(text: string): string {
    const textarea = document.createElement('textarea');
    textarea.innerHTML = text;
    return textarea.value;
  }

  /**
   * Prevent XSS by encoding special characters
   */
  static preventXSS(input: string): string {
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;',
    };

    return input.replace(/[&<>"'\/]/g, (char) => map[char]);
  }

  /**
   * Sanitize URL to prevent javascript: protocol
   */
  static sanitizeURL(url: string): string {
    if (!url) {
      return '';
    }

    // Remove dangerous protocols
    const dangerousProtocols = ['javascript:', 'data:', 'vbscript:'];
    const lowerURL = url.toLowerCase().trim();

    for (const protocol of dangerousProtocols) {
      if (lowerURL.startsWith(protocol)) {
        return '';
      }
    }

    return url;
  }

  /**
   * Strip dangerous tags like script, iframe, etc.
   */
  static stripDangerousTags(html: string): string {
    let result = html;

    for (const tag of this.DANGEROUS_TAGS) {
      const regex = new RegExp(`<${tag}[^>]*>.*?<\\/${tag}>`, 'gi');
      result = result.replace(regex, '');

      // Also handle self-closing tags
      const selfClosingRegex = new RegExp(`<${tag}[^>]*\\/>`, 'gi');
      result = result.replace(selfClosingRegex, '');
    }

    return result;
  }

  /**
   * Remove dangerous attributes (event handlers)
   */
  static removeDangerousAttributes(html: string): string {
    let result = html;

    for (const attr of this.DANGEROUS_ATTRIBUTES) {
      const regex = new RegExp(`\\s${attr}\\s*=\\s*["\']?[^"\'\\s>]*["\']?`, 'gi');
      result = result.replace(regex, '');
    }

    return result;
  }

  /**
   * Remove script tags and content
   */
  static removeScripts(html: string): string {
    const regex = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi;
    return html.replace(regex, '');
  }

  /**
   * Normalize whitespace
   */
  static normalizeWhitespace(text: string): string {
    return text
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Sanitize JSON data
   */
  static sanitizeJSON(jsonString: string): Record<string, any> | null {
    try {
      const parsed = JSON.parse(jsonString);
      return this.sanitizeObject(parsed);
    } catch {
      return null;
    }
  }

  /**
   * Recursively sanitize object values
   */
  private static sanitizeObject(
    obj: any
  ): Record<string, any> | string | any {
    if (typeof obj === 'string') {
      return this.sanitizeInput(obj);
    }

    if (Array.isArray(obj)) {
      return obj.map((item) => this.sanitizeObject(item));
    }

    if (obj !== null && typeof obj === 'object') {
      const sanitized: Record<string, any> = {};
      for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          sanitized[key] = this.sanitizeObject(obj[key]);
        }
      }
      return sanitized;
    }

    return obj;
  }

  /**
   * Strip HTML tags completely
   */
  static stripTags(html: string): string {
    const regex = /<[^>]*>/g;
    return html.replace(regex, '');
  }

  /**
   * Sanitize file name to prevent path traversal
   */
  static sanitizeFileName(fileName: string): string {
    // Remove path traversal attempts
    const sanitized = fileName
      .replace(/\.\./g, '')
      .replace(/[\/\\]/g, '')
      .replace(/[^a-zA-Z0-9._-]/g, '');

    return sanitized || 'file';
  }

  /**
   * Sanitize CSS to prevent CSS injection
   */
  static sanitizeCSS(css: string): string {
    // Remove dangerous CSS properties
    const dangerousProps = [
      'behavior',
      '-moz-binding',
      'expression',
      'javascript:',
    ];

    let sanitized = css;
    for (const prop of dangerousProps) {
      const regex = new RegExp(`${prop}\\s*:`, 'gi');
      sanitized = sanitized.replace(regex, '');
    }

    return sanitized;
  }
}
