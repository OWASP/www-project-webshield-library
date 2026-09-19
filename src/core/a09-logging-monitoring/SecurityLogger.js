const DEFAULT_REDACT_KEYS = ["password", "token", "secret", "authorization", "cookie"];

// Catches secrets logged under an unlisted field name. JWTs reliably start with
// "eyJ" (base64url of `{"`), so this has a very low false-positive rate.
const DEFAULT_VALUE_PATTERNS = [/^eyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]*$/i];

const MAX_REDACT_DEPTH = 20;

export class SecurityLogger {
  /**
   * @param {{sink?: (entry: object) => void, redactKeys?: string[], valuePatterns?: RegExp[]}} [options]
   */
  constructor(options = {}) {
    this.sink = options.sink || ((entry) => console.log(JSON.stringify(entry)));
    this.redactKeys = options.redactKeys || DEFAULT_REDACT_KEYS;
    this.valuePatterns = options.valuePatterns || DEFAULT_VALUE_PATTERNS;
  }

  _looksSensitive(value) {
    return typeof value === "string" && this.valuePatterns.some((pattern) => pattern.test(value));
  }

  redact(value, seen = new WeakSet(), depth = 0) {
    if (depth >= MAX_REDACT_DEPTH) return "[MaxDepth]";

    if (Array.isArray(value)) {
      if (seen.has(value)) return "[Circular]";
      seen.add(value);
      return value.map((item) => this.redact(item, seen, depth + 1));
    }

    if (value && typeof value === "object") {
      if (seen.has(value)) return "[Circular]";
      seen.add(value);
      const next = {};
      for (const [key, val] of Object.entries(value)) {
        const shouldRedact = this.redactKeys.some((k) => key.toLowerCase().includes(k));
        next[key] = shouldRedact || this._looksSensitive(val) ? "[REDACTED]" : this.redact(val, seen, depth + 1);
      }
      return next;
    }

    return this._looksSensitive(value) ? "[REDACTED]" : value;
  }

  log(level, event, details = {}) {
    this.sink({
      ts: new Date().toISOString(),
      level,
      event,
      details: this.redact(details)
    });
  }

  info(event, details = {}) {
    this.log("info", event, details);
  }

  warn(event, details = {}) {
    this.log("warn", event, details);
  }

  error(event, details = {}) {
    this.log("error", event, details);
  }
}