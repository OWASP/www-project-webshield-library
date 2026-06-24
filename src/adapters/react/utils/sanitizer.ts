const ALLOWED_TAGS = new Set([
  'b', 'i', 'em', 'strong', 'u', 'br', 'p', 'ul', 'ol', 'li',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'img',
]);

const ALLOWED_ATTRIBUTES: Record<string, string[]> = {
  a: ['href', 'title', 'target'],
  img: ['src', 'alt', 'title'],
};

const SAFE_PROTOCOLS = ['http:', 'https:', 'mailto:'];

function isSafeURL(url: string): boolean {
  try {
    const parsed = new URL(
      url,
      typeof window !== 'undefined' ? window.location.href : 'http://localhost'
    );
    return SAFE_PROTOCOLS.includes(parsed.protocol);
  } catch {
    return false;
  }
}

export class Sanitizer {
  /**
   * Strip dangerous content from a plain-text / minimal-HTML string.
   * Removes <script> tags and event-handler attributes.
   */
  static sanitizeInput(input: string): string {
    if (!input || typeof input !== 'string') return '';
    let out = input.replace(
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      ''
    );
    out = out.replace(/\bon\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)/gi, '');
    return out.trim();
  }

  /**
   * Encode special HTML characters — safe for placing content in an HTML context.
   */
  static encodeHTML(str: string): string {
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '/': '&#x2F;',
    };
    return str.replace(/[&<>"'/]/g, (c) => map[c]);
  }

  /**
   * Full HTML sanitizer using a tag + attribute whitelist.
   * Falls back to stripping all tags in server-side environments.
   */
  static sanitizeHTML(html: string): string {
    if (typeof DOMParser === 'undefined') {
      return html.replace(/<[^>]*>/g, '');
    }

    const doc = new DOMParser().parseFromString(html, 'text/html');

    function walk(node: Node): void {
      const toRemove: Element[] = [];
      node.childNodes.forEach((child) => {
        if (child.nodeType !== Node.ELEMENT_NODE) return;
        const el = child as Element;
        const tag = el.tagName.toLowerCase();

        if (!ALLOWED_TAGS.has(tag)) {
          toRemove.push(el);
          return;
        }

        const allowed = ALLOWED_ATTRIBUTES[tag] ?? [];
        Array.from(el.attributes).forEach((attr) => {
          if (!allowed.includes(attr.name)) {
            el.removeAttribute(attr.name);
          }
        });

        if ((tag === 'a' || tag === 'img') && el.hasAttribute('href')) {
          if (!isSafeURL(el.getAttribute('href')!)) el.removeAttribute('href');
        }
        if (tag === 'img' && el.hasAttribute('src')) {
          if (!isSafeURL(el.getAttribute('src')!)) el.removeAttribute('src');
        }

        walk(el);
      });

      toRemove.forEach((el) => {
        const text = document.createTextNode(el.textContent ?? '');
        node.insertBefore(text, el);
        node.removeChild(el);
      });
    }

    walk(doc.body);
    return doc.body.innerHTML;
  }

  /**
   * Strip ALL HTML tags, returning plain text.
   */
  static stripTags(html: string): string {
    return html.replace(/<[^>]*>/g, '');
  }

  /**
   * Sanitize a URL, returning empty string if it uses a dangerous protocol.
   */
  static sanitizeURL(url: string): string {
    if (!url) return '';
    return isSafeURL(url) ? url : '';
  }
}
