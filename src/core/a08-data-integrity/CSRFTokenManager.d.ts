export class CSRFTokenManager {
    /**
     * Double-submit cookie pattern: the server sets a readable (non-HttpOnly) cookie
     * and compares it with the header. The cookie is read on every request, so the
     * header always carries the server's current token. Browser only.
     * @param {string} [cookieName]
     */
    static fromCookie(cookieName?: string): CSRFTokenManager;
    /**
     * @param {{storage?: {get:()=>string|null,set:(value:string)=>void}, tokenLength?: number}} [options]
     */
    constructor(options?: {
        storage?: {
            get: () => string | null;
            set: (value: string) => void;
        };
        tokenLength?: number;
    });
    storage: {
        get: () => any;
        set: (v: any) => void;
    };
    tokenLength: number;
    generateToken(): string;
    getToken(): any;
    rotateToken(): string;
    /**
     * Stores a token issued by the server (synchronizer-token pattern), e.g. from a
     * login response or a `<meta name="csrf-token">` tag. A token generated in the
     * browser proves nothing to the server; it has to validate one it issued itself.
     */
    setToken(token: any): string;
    attach(headers?: {}): {};
    validate(token: any): boolean;
}
