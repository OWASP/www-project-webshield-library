/**
 * Parses a JSON request body. Returns `undefined` for an empty body, and
 * throws 415 for a non-JSON content type, 413 over `limit` bytes and 400 for
 * malformed JSON.
 * @param {Request} request
 * @param {{limit?: number}} [options]
 * @returns {Promise<unknown>}
 */
export function readJsonBody(request: Request, { limit }?: {
    limit?: number;
}): Promise<unknown>;
export const DEFAULT_BODY_LIMIT: number;
