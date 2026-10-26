/**
 * Fields that identify a request in a security log entry. The query string is
 * left out (see `getPath()`), and no headers other than the request id are
 * copied, so tokens and cookies never reach the log in the first place.
 */
export function requestLogContext(req: any): {
    method: string;
    path: string;
};
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
export function logRequestError(logger: {
    warn: Function;
    error: Function;
}, error: unknown, req?: any): void;
