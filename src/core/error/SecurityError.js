// Registry symbols are shared across realms and copies of this module, so a
// SecurityError created by one copy of the package (a second installed version,
// or a `modules/*` import next to the root import) still passes `instanceof`
// against another copy's class.
const SECURITY_ERROR_BRAND = Symbol.for("@owasp-webshield/core.SecurityError");
const BASE_CLASS = Symbol.for("@owasp-webshield/core.SecurityError.base");

/**
 * Typed security error with normalized code and optional metadata.
 */
export class SecurityError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {Record<string, unknown>} [details]
   */
  constructor(code, message, details = {}) {
    super(message);
    this.name = "SecurityError";
    this.code = code;
    this.details = details;
    Object.defineProperty(this, SECURITY_ERROR_BRAND, { value: true });
  }

  // Only the base class matches by brand; subclasses keep normal prototype checks.
  static [Symbol.hasInstance](value) {
    if (Object.hasOwn(this, BASE_CLASS)) {
      return Boolean(value && typeof value === "object" && value[SECURITY_ERROR_BRAND] === true);
    }
    return Function.prototype[Symbol.hasInstance].call(this, value);
  }
}

Object.defineProperty(SecurityError, BASE_CLASS, { value: true });

export const SecurityErrorCode = Object.freeze({
  INVALID_INPUT: "INVALID_INPUT",
  AUTH_REQUIRED: "AUTH_REQUIRED",
  TOKEN_EXPIRED: "TOKEN_EXPIRED",
  ACCESS_DENIED: "ACCESS_DENIED",
  CSRF_INVALID: "CSRF_INVALID",
  MISCONFIGURATION: "MISCONFIGURATION",
  SSRF_BLOCKED: "SSRF_BLOCKED",
  CRYPTO_ERROR: "CRYPTO_ERROR",
  CREDENTIAL_LEAK_BLOCKED: "CREDENTIAL_LEAK_BLOCKED"
});