import React, { useMemo } from 'react';

const ALLOWED_TAGS = new Set([
  'b', 'i', 'em', 'strong', 'u', 'br', 'p', 'ul', 'ol', 'li',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
]);

const SAFE_PROTOCOLS = new Set(['http:', 'https:', 'mailto:']);

function isValidHref(url: string): boolean {
  try {
    const parsed = new URL(url, typeof window !== 'undefined' ? window.location.href : 'http://localhost');
    return SAFE_PROTOCOLS.has(parsed.protocol);
  } catch {
    return false;
  }
}

/**
 * Sanitizes an HTML string to only allowed tags, stripping event handlers and
 * dangerous protocols. Runs entirely in-memory using DOMParser when available.
 */
function sanitizeHTML(html: string): string {
  if (typeof DOMParser === 'undefined') {
    // Server-side: strip all tags as safe fallback
    return html.replace(/<[^>]*>/g, '');
  }

  const doc = new DOMParser().parseFromString(html, 'text/html');

  function clean(node: Node): void {
    const toRemove: Node[] = [];
    node.childNodes.forEach((child) => {
      if (child.nodeType === Node.ELEMENT_NODE) {
        const el = child as Element;
        const tag = el.tagName.toLowerCase();
        if (!ALLOWED_TAGS.has(tag) && tag !== 'a') {
          // Replace with its text content (don't just remove to preserve text)
          const text = document.createTextNode(el.textContent ?? '');
          node.insertBefore(text, el);
          toRemove.push(el);
        } else {
          // Strip all attributes except safe href
          Array.from(el.attributes).forEach((attr) => {
            if (tag === 'a' && attr.name === 'href') {
              if (!isValidHref(attr.value)) el.removeAttribute('href');
            } else {
              el.removeAttribute(attr.name);
            }
          });
          clean(el);
        }
      }
    });
    toRemove.forEach((n) => n.parentNode?.removeChild(n));
  }

  clean(doc.body);
  return doc.body.innerHTML;
}

export interface SanitizedContentProps {
  html: string;
  /** HTML tag to render as (default: div) */
  as?: keyof JSX.IntrinsicElements;
  className?: string;
}

/**
 * Renders sanitized HTML content, safe against XSS (A03).
 * Uses a whitelist of allowed tags and removes all event handlers.
 */
export const SanitizedContent: React.FC<SanitizedContentProps> = ({
  html,
  as: Tag = 'div',
  className,
}) => {
  const safeHTML = useMemo(() => sanitizeHTML(html), [html]);
  return (
    // eslint-disable-next-line react/no-danger
    <Tag
      className={className}
      dangerouslySetInnerHTML={{ __html: safeHTML }}
    />
  );
};
