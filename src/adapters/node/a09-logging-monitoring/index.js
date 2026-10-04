import { SecurityError } from "@owasp-webshield/core";
import { statusForSecurityError, toErrorResponse } from "../error/index.js";
import { getHeader, getMethod, getPath } from "../http/request.js";

/**
 * Fields that identify a request in a security log entry. The query string is
 * left out (see `getPath()`), and no headers other than the request id are
 * copied, so tokens and cookies never reach the log in the first place.
 */
export function requestLogContext(req) {
  const context = { method: getMethod(req), path: getPath(req) };
  const ip = req?.ip ?? req?.socket?.remoteAddress;
  if (ip) context.ip = ip;
  const requestId = getHeader(req, "x-request-id");
  if (requestId) context.requestId = String(requestId).slice(0, 128);
  return context;
}

/**
 * Logs a request failure through a `SecurityLogger` (which redacts the details).
 * Security rejections (401/403/400) are logged at `warn` as
 * `security.<code>` events, so alerting can count denials and failed logins;
 * everything else is logged at `error` as `request.failed`.
 *
 * @param {{warn: Function, error: Function}} logger
 * @param {unknown} error
 * @param {any} [req]
 */
export function logRequestError(logger, error, req) {
  if (!logger) return;
  const context = req ? requestLogContext(req) : {};

  if (error instanceof SecurityError) {
    const status = statusForSecurityError(error.code);
    const level = status >= 500 ? "error" : "warn";
    logger[level](`security.${error.code.toLowerCase()}`, { ...context, status, message: error.message, details: error.details });
    return;
  }

  const { status } = toErrorResponse(error);
  if (status < 500) {
    logger.warn("request.rejected", { ...context, status });
    return;
  }
  logger.error("request.failed", { ...context, status, message: error instanceof Error ? error.message : String(error) });
}
