import { SecurityError, SecurityErrorCode } from "@owasp-webshield/core";

const STATUS_BY_CODE = Object.freeze({
  [SecurityErrorCode.INVALID_INPUT]: 400,
  [SecurityErrorCode.AUTH_REQUIRED]: 401,
  [SecurityErrorCode.TOKEN_EXPIRED]: 401,
  [SecurityErrorCode.ACCESS_DENIED]: 403,
  [SecurityErrorCode.CSRF_INVALID]: 403,
  [SecurityErrorCode.SSRF_BLOCKED]: 403,
  [SecurityErrorCode.CREDENTIAL_LEAK_BLOCKED]: 403,
  [SecurityErrorCode.MISCONFIGURATION]: 500,
  [SecurityErrorCode.CRYPTO_ERROR]: 500
});

/**
 * HTTP status for a `SecurityErrorCode`; unknown codes map to 500.
 * @param {string} code
 */
export function statusForSecurityError(code) {
  return STATUS_BY_CODE[code] || 500;
}

// Client errors raised by body parsers and other middleware that follow the
// `http-errors` convention (`status` + `expose`), e.g. malformed JSON or a body
// over the size limit. Without this they would be reported as a 500.
function clientErrorStatus(error) {
  const status = Number(error?.status ?? error?.statusCode);
  return Number.isInteger(status) && status >= 400 && status < 500 ? status : null;
}

/**
 * Turns any thrown value into a response that is safe to send. Server-side
 * failures (5xx) never expose their message, since it can carry stack details,
 * file paths or secrets; `SecurityError` details are not sent either, except the
 * per-field validation errors of an `INVALID_INPUT` (field, rule and message only,
 * never the submitted value).
 * @param {unknown} error
 * @param {{exposeMessages?: boolean}} [options] set false to send only the error code
 * @returns {{status: number, headers: Record<string, string>, body: Record<string, unknown>}}
 */
export function toErrorResponse(error, { exposeMessages = true } = {}) {
  const headers = {};

  if (error instanceof SecurityError) {
    const status = statusForSecurityError(error.code);
    if (status >= 500) return { status, headers, body: { error: "internal_error" } };

    const body = { error: error.code };
    if (exposeMessages) body.message = error.message;
    if (error.code === SecurityErrorCode.INVALID_INPUT && Array.isArray(error.details?.errors)) {
      body.errors = error.details.errors.map(({ field, code, message }) => ({ field, code, message }));
    }
    // RFC 6750 section 3: a 401 for a bearer-protected resource names the scheme.
    if (error.code === SecurityErrorCode.AUTH_REQUIRED) headers["WWW-Authenticate"] = "Bearer";
    if (error.code === SecurityErrorCode.TOKEN_EXPIRED) headers["WWW-Authenticate"] = 'Bearer error="invalid_token"';
    return { status, headers, body };
  }

  const clientStatus = clientErrorStatus(error);
  if (clientStatus) {
    const body = { error: "bad_request" };
    if (exposeMessages && error.expose === true && typeof error.message === "string") body.message = error.message;
    return { status: clientStatus, headers, body };
  }

  return { status: 500, headers, body: { error: "internal_error" } };
}
