/**
 * HTTP status for a `SecurityErrorCode`; unknown codes map to 500.
 * @param {string} code
 */
export function statusForSecurityError(code: string): any;
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
export function toErrorResponse(error: unknown, { exposeMessages }?: {
    exposeMessages?: boolean;
}): {
    status: number;
    headers: Record<string, string>;
    body: Record<string, unknown>;
};
