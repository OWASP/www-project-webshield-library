// Void (self-closing) elements that never carry a separate close tag.
const VOID_ELEMENTS = new Set([
  "area", "base", "br", "col", "embed", "hr", "img", "input",
  "link", "meta", "param", "source", "track", "wbr"
]);

// Tags whose tag *and* entire nested content must never survive sanitization,
// regardless of profile - these are active-content or script-capable contexts.
const STRIP_CONTENT_TAGS = new Set([
  "script", "style", "iframe", "object", "embed", "noembed",
  "noscript", "template", "svg", "math"
]);

// Formatting tags allowed to remain (unwrapped otherwise) in the "moderate" profile.
const MODERATE_ALLOWED_TAGS = new Set([
  "a", "b", "strong", "i", "em", "u", "p", "br", "span", "div",
  "ul", "ol", "li", "blockquote", "code", "pre", "img",
  "h1", "h2", "h3", "h4", "h5", "h6"
]);

const GLOBAL_ALLOWED_ATTRS = new Set(["title", "class"]);
const TAG_ALLOWED_ATTRS = {
  a: new Set(["href", "target", "rel"]),
  img: new Set(["src", "alt", "width", "height"])
};
const URL_ATTRS = new Set(["href", "src"]);
const SAFE_URL_PROTOCOLS = new Set(["http:", "https:", "mailto:", "tel:"]);

const NAMED_ENTITIES = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'",
  // Named refs an attacker can use to hide a URL scheme separator/whitespace, e.g.
  // "javascript&colon;alert(1)" decodes to "javascript:alert(1)" in a real browser.
  colon: ":", tab: "\t", newline: "\n"
};

// Attribute values are entity-decoded before scheme checks, since browsers do the
// same before interpreting a URL - otherwise "&#106;avascript:" bypasses the filter.
function decodeEntities(value) {
  return String(value).replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (match, ref) => {
    if (ref[0] === "#") {
      const codePoint = ref[1].toLowerCase() === "x" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      return Number.isNaN(codePoint) ? match : String.fromCodePoint(codePoint);
    }
    return NAMED_ENTITIES[ref.toLowerCase()] || match;
  });
}

function encodeText(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function encodeAttrValue(value) {
  return String(value).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Browsers strip tabs/newlines/whitespace from a URL before reading its scheme,
// so "java\tscript:" and similar whitespace-obfuscated payloads must too.
function isSafeUrl(rawValue) {
  const normalized = decodeEntities(rawValue).replace(/\s+/g, "");
  const schemeMatch = /^([a-z][a-z0-9+.-]*):/i.exec(normalized);
  if (!schemeMatch) return true; // relative URL - no scheme to police
  return SAFE_URL_PROTOCOLS.has(`${schemeMatch[1].toLowerCase()}:`);
}

// Attribute boundaries are whitespace OR "/" (browsers parse `<img/onerror=x>` as
// having an "onerror" attribute), so the name/value grammar must treat both as separators.
function parseAttrs(raw) {
  const attrs = {};
  const attrRegex = /([^\s/>][^\s/=>]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let match;
  while ((match = attrRegex.exec(raw)) !== null) {
    const name = match[1].toLowerCase();
    attrs[name] = match[2] ?? match[3] ?? match[4] ?? "";
  }
  return attrs;
}

// Minimal HTML tokenizer: splits markup into text/open/close tokens without
// executing or trusting any embedded markup, unlike sequential regex substitution.
function tokenizeHTML(html) {
  const tokens = [];
  let i = 0;
  const n = html.length;

  while (i < n) {
    if (html[i] !== "<") {
      const next = html.indexOf("<", i);
      const value = next === -1 ? html.slice(i) : html.slice(i, next);
      if (value) tokens.push({ type: "text", value });
      i = next === -1 ? n : next;
      continue;
    }

    if (html.startsWith("<!--", i)) {
      const end = html.indexOf("-->", i + 4);
      i = end === -1 ? n : end + 3;
      continue;
    }

    if (html[i + 1] === "!" || html[i + 1] === "?") {
      const end = html.indexOf(">", i);
      i = end === -1 ? n : end + 1;
      continue;
    }

    const tagMatch = /^<(\/?)([a-zA-Z][a-zA-Z0-9-]*)/.exec(html.slice(i));
    if (!tagMatch) {
      tokens.push({ type: "text", value: "<" });
      i += 1;
      continue;
    }

    const isClosing = tagMatch[1] === "/";
    const tagName = tagMatch[2].toLowerCase();
    let j = i + tagMatch[0].length;
    let quote = null;
    while (j < n) {
      const ch = html[j];
      if (quote) {
        if (ch === quote) quote = null;
      } else if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === ">") {
        break;
      }
      j += 1;
    }

    const rawAttrs = html.slice(i + tagMatch[0].length, j);
    tokens.push({
      type: isClosing ? "close" : "open",
      name: tagName,
      attrs: isClosing ? null : parseAttrs(rawAttrs),
      selfClosing: VOID_ELEMENTS.has(tagName) || /\/\s*$/.test(rawAttrs)
    });
    i = j < n ? j + 1 : n;
  }

  return tokens;
}

function sanitizeAttrs(tagName, attrs) {
  const safeAttrs = [];
  for (const [name, value] of Object.entries(attrs)) {
    if (name.startsWith("on") || name === "style") continue;
    const isAllowed = GLOBAL_ALLOWED_ATTRS.has(name) || TAG_ALLOWED_ATTRS[tagName]?.has(name);
    if (!isAllowed) continue;
    if (URL_ATTRS.has(name) && !isSafeUrl(value)) continue;
    safeAttrs.push(`${name}="${encodeAttrValue(decodeEntities(value))}"`);
  }
  return safeAttrs.length ? ` ${safeAttrs.join(" ")}` : "";
}

function sanitizeTokens(tokens, { allowTags }) {
  let output = "";
  const stripStack = [];

  for (const token of tokens) {
    if (stripStack.length > 0) {
      if (token.type === "close" && token.name === stripStack[stripStack.length - 1]) {
        stripStack.pop();
      } else if (token.type === "open" && STRIP_CONTENT_TAGS.has(token.name) && !token.selfClosing) {
        stripStack.push(token.name);
      }
      continue;
    }

    if (token.type === "text") {
      output += encodeText(token.value);
      continue;
    }

    if (STRIP_CONTENT_TAGS.has(token.name)) {
      if (token.type === "open" && !token.selfClosing) stripStack.push(token.name);
      continue;
    }

    if (!allowTags || !allowTags.has(token.name)) {
      continue; // unwrap: drop the tag markup itself, sibling text still comes through
    }

    if (token.type === "close") {
      output += `</${token.name}>`;
      continue;
    }

    const attrString = sanitizeAttrs(token.name, token.attrs);
    output += token.selfClosing ? `<${token.name}${attrString} />` : `<${token.name}${attrString}>`;
  }

  return output;
}

export class InputSanitizer {
  constructor(profile = "strict") {
    this.profile = profile === "moderate" ? "moderate" : "strict";
  }

  sanitizeHTML(input) {
    const tokens = tokenizeHTML(String(input || ""));
    return sanitizeTokens(tokens, {
      allowTags: this.profile === "moderate" ? MODERATE_ALLOWED_TAGS : null
    });
  }
}