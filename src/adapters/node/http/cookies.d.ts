/**
 * Every value sent for `name`, in header order. More than one value means the
 * cookie was also set from another path or a parent domain (cookie tossing),
 * which callers that rely on the cookie for security should reject.
 * @returns {string[]}
 */
export function getCookieValues(req: any, name: any): string[];
/**
 * Serializes a `Set-Cookie` value with secure defaults (`Secure`, `SameSite=Strict`,
 * `Path=/`). `HttpOnly` defaults to true; turn it off only for a cookie the
 * browser has to read, such as a double-submit CSRF token.
 * @param {string} name
 * @param {string} value
 * @param {{path?: string, domain?: string, maxAge?: number, secure?: boolean, httpOnly?: boolean, sameSite?: "Strict"|"Lax"|"None"}} [options]
 */
export function serializeCookie(name: string, value: string, options?: {
    path?: string;
    domain?: string;
    maxAge?: number;
    secure?: boolean;
    httpOnly?: boolean;
    sameSite?: "Strict" | "Lax" | "None";
}): string;
