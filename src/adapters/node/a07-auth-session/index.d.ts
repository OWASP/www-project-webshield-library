/**
 * The token from an `Authorization: Bearer <token>` header, or null.
 * @param {any} req
 * @returns {string | null}
 */
export function extractBearerToken(req: any): string | null;
/**
 * Authenticates one request. The server holds no session state of its own:
 * `verifyToken` is where the app checks the token (JWT verification, a session
 * store lookup, token introspection) and returns that user's session, or null.
 * Unlike `AuthManager`, which holds the single session of a browser tab, every
 * call here is independent, so concurrent requests from different users never
 * share state.
 *
 * @param {any} req a Node IncomingMessage, an Express request or a Fetch Request
 * @param {{
 *   verifyToken: (token: string, req: any) => ({userId: string|number, roles?: string[], metadata?: Record<string, any>} | null | Promise<{userId: string|number, roles?: string[], metadata?: Record<string, any>} | null>),
 *   getToken?: (req: any) => string|null
 * }} options
 * @returns {Promise<{userId: string, roles: string[], metadata: Record<string, any>}>}
 */
export function authenticate(req: any, { verifyToken, getToken }?: {
    verifyToken: (token: string, req: any) => ({
        userId: string | number;
        roles?: string[];
        metadata?: Record<string, any>;
    } | null | Promise<{
        userId: string | number;
        roles?: string[];
        metadata?: Record<string, any>;
    } | null>);
    getToken?: (req: any) => string | null;
}): Promise<{
    userId: string;
    roles: string[];
    metadata: Record<string, any>;
}>;
