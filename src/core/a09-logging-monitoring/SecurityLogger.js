const DEFAULT_REDACT_KEYS = ["password", "token", "secret", "authorization", "cookie"];

export class SecurityLogger {
  /**
   * @param {{sink?: (entry: object) => void, redactKeys?: string[]}} [options]
   */
  constructor(options = {}) {
    this.sink = options.sink || ((entry) => console.log(JSON.stringify(entry)));
    this.redactKeys = options.redactKeys || DEFAULT_REDACT_KEYS;
  }

  redact(value) {
    if (Array.isArray(value)) {
      return value.map((item) => this.redact(item));
    }
    if (value && typeof value === "object") {
      const next = {};
      for (const [key, val] of Object.entries(value)) {
        const shouldRedact = this.redactKeys.some((k) => key.toLowerCase().includes(k));
        next[key] = shouldRedact ? "[REDACTED]" : this.redact(val);
      }
      return next;
    }
    return value;
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