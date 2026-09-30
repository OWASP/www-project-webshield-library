export class InputValidator {
  validateSchema(input, schema) {
    const errors = [];
    for (const [key, rule] of Object.entries(schema)) {
      const value = input[key];
      if (rule.required && (value === undefined || value === null || value === "")) {
        errors.push({ field: key, code: "required", message: `${key} is required` });
        continue;
      }
      if (value === undefined || value === null) continue;

      if (rule.type && typeof value !== rule.type) {
        errors.push({ field: key, code: "type", message: `${key} must be ${rule.type}` });
      }
      if (rule.minLength && String(value).length < rule.minLength) {
        errors.push({ field: key, code: "minLength", message: `${key} must be at least ${rule.minLength}` });
      }
      if (rule.maxLength && String(value).length > rule.maxLength) {
        errors.push({ field: key, code: "maxLength", message: `${key} must be at most ${rule.maxLength}` });
      }
      // A copy without the g/y flags: those make RegExp#test() stateful (lastIndex),
      // so the same valid value would alternately pass and fail.
      const pattern = rule.pattern && new RegExp(rule.pattern.source, rule.pattern.flags.replace(/[gy]/g, ""));
      if (pattern && !pattern.test(String(value))) {
        errors.push({ field: key, code: "pattern", message: `${key} format is invalid` });
      }
    }
    return { valid: errors.length === 0, errors };
  }

  // Same acceptance as /^[^\s@]+@[^\s@]+\.[^\s@]+$/ (one "@", non-empty local part,
  // a dot inside the domain, no whitespace), checked in linear time: that regex
  // backtracks quadratically on domains with many dots ("a@a.a.a.a...@").
  validateEmail(value) {
    const input = String(value || "");
    if (/\s/.test(input)) return false;
    const at = input.indexOf("@");
    if (at <= 0 || input.indexOf("@", at + 1) !== -1) return false;
    const domain = input.slice(at + 1);
    return domain.slice(1, -1).includes(".");
  }

  validateUrl(value) {
    try {
      const url = new URL(String(value || ""));
      return ["http:", "https:"].includes(url.protocol);
    } catch {
      return false;
    }
  }

  validateLength(value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
    const len = String(value || "").length;
    return len >= min && len <= max;
  }
}