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
  }
}

export const SecurityErrorCode = Object.freeze({
  INVALID_INPUT: "INVALID_INPUT",
  AUTH_REQUIRED: "AUTH_REQUIRED",
  TOKEN_EXPIRED: "TOKEN_EXPIRED",
  ACCESS_DENIED: "ACCESS_DENIED",
  CSRF_INVALID: "CSRF_INVALID",
  MISCONFIGURATION: "MISCONFIGURATION",
  SSRF_BLOCKED: "SSRF_BLOCKED",
  CRYPTO_ERROR: "CRYPTO_ERROR"
});