/**
 * Request accessors shared by every helper in this package. They accept a Node
 * `IncomingMessage` (plain `node:http`, Express, Connect, Fastify's `request.raw`)
 * and a Fetch API `Request` (Next.js route handlers, Hono, Workers), so a future
 * framework adapter only has to wrap these helpers, not re-implement them.
 */
/**
 * @param {{headers?: Record<string, string|string[]|undefined> | {get: (name: string) => string|null}}} req
 * @param {string} name
 * @returns {string|undefined}
 */
export function getHeader(req: {
    headers?: Record<string, string | string[] | undefined> | {
        get: (name: string) => string | null;
    };
}, name: string): string | undefined;
export function getMethod(req: any): string;
/**
 * Path without the query string: query strings carry OAuth codes, signed-link
 * signatures and reset tokens, which must not end up in logs.
 */
export function getPath(req: any): string;
