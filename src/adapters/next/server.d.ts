/**
 * Auth for Server Components, Server Actions and route handlers, which have no
 * request object to pass: it reads the current request's headers through
 * `headers()` from next/headers. Configure it once, e.g. in `lib/auth.js`:
 *
 * ```js
 * export const { getSession, requireSession, requirePermission } = createServerAuth({
 *   verifyToken: (token) => sessions.lookup(token),
 *   getToken: cookieToken("session"),
 *   checker: owl
 * });
 * ```
 *
 * `verifyToken` is called on every call, so cache the lookup (React's `cache()`)
 * if a page calls it more than once per request.
 *
 * @param {Parameters<typeof createServerAuthWith>[1]} options
 */
export function createServerAuth(options: Parameters<typeof createServerAuthWith>[1]): {
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
import { createServerAuthWith } from "./session.js";
