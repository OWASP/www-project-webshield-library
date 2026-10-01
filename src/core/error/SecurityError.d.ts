/**
 * Typed security error with normalized code and optional metadata.
 */
export class SecurityError extends Error {
    static [Symbol.hasInstance](value: any): any;
    /**
     * @param {string} code
     * @param {string} message
     * @param {Record<string, unknown>} [details]
     */
    constructor(code: string, message: string, details?: Record<string, unknown>);
    code: string;
    details: Record<string, unknown>;
}
export const SecurityErrorCode: Readonly<{
    INVALID_INPUT: "INVALID_INPUT";
    AUTH_REQUIRED: "AUTH_REQUIRED";
    TOKEN_EXPIRED: "TOKEN_EXPIRED";
    ACCESS_DENIED: "ACCESS_DENIED";
    CSRF_INVALID: "CSRF_INVALID";
    MISCONFIGURATION: "MISCONFIGURATION";
    SSRF_BLOCKED: "SSRF_BLOCKED";
    CRYPTO_ERROR: "CRYPTO_ERROR";
    CREDENTIAL_LEAK_BLOCKED: "CREDENTIAL_LEAK_BLOCKED";
}>;
