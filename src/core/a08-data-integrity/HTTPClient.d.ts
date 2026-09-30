export class HTTPClient {
    /**
     * @param {{baseUrl?: string, csrfManager?: import('./CSRFTokenManager.js').CSRFTokenManager, tokenProvider?: ()=>Promise<string|null>|string|null, fetchImpl?: typeof fetch, outboundRequestPolicy?: { validateUrl: (url: string) => unknown }, allowedOrigins?: string[]}} [options]
     */
    constructor(options?: {
        baseUrl?: string;
        csrfManager?: import("./CSRFTokenManager.js").CSRFTokenManager;
        tokenProvider?: () => Promise<string | null> | string | null;
        fetchImpl?: typeof fetch;
        outboundRequestPolicy?: {
            validateUrl: (url: string) => unknown;
        };
        allowedOrigins?: string[];
    });
    baseUrl: string;
    csrfManager: import("./CSRFTokenManager.js").CSRFTokenManager;
    tokenProvider: () => Promise<string | null> | string | null;
    fetchImpl: (...args: any[]) => Promise<Response>;
    outboundRequestPolicy: {
        validateUrl: (url: string) => unknown;
    };
    allowedOrigins: Set<string>;
    requestInterceptors: any[];
    responseInterceptors: any[];
    addRequestInterceptor(interceptor: any): void;
    addResponseInterceptor(interceptor: any): void;
    _isCredentialSafeOrigin(requestUrl: any): boolean;
    request(url: any, options?: {}): Promise<{
        ok: boolean;
        status: number;
        headers: Headers;
        data: any;
        error: any;
        raw: Response;
    }>;
    _followRedirects(requestUrl: any, config: any, policy: any): Promise<Response>;
}
