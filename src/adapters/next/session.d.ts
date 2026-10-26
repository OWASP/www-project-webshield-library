/**
 * A `getToken` for `authenticate()` / `withOwl({ auth })` that reads the session
 * token from a cookie instead of the `Authorization` header, which is how a
 * browser authenticates page loads and Server Actions. A cookie sent more than
 * once (cookie tossing) counts as no token.
 * @param {string} name
 * @returns {(req: any) => string | null}
 */
export function cookieToken(name: string): (req: any) => string | null;
/**
 * The server-side auth helpers, reading the request headers through
 * `getHeaders` (`headers()` from next/headers in `@owasp-webshield/next/server`).
 * @param {() => any} getHeaders
 * @param {{
 *   verifyToken: NonNullable<Parameters<typeof authenticate>[1]>["verifyToken"],
 *   getToken?: (req: any) => string | null,
 *   checker?: object
 * }} options
 */
export function createServerAuthWith(getHeaders: () => any, { verifyToken, getToken, checker }: {
    verifyToken: NonNullable<Parameters<typeof authenticate>[1]>["verifyToken"];
    getToken?: (req: any) => string | null;
    checker?: object;
}): {
    getSession: () => Promise<{
        userId: string;
        roles: string[];
        metadata: Record<string, any>;
    } | null>;
    requireSession: () => Promise<{
        userId: string;
        roles: string[];
        metadata: Record<string, any>;
    }>;
    requirePermission: (action: string, resource: string) => Promise<{
        userId: string;
        roles: string[];
        metadata: Record<string, any>;
    }>;
};
import { authenticate } from "@owasp-webshield/node";
