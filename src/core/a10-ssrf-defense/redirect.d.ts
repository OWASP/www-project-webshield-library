/** True when `headers` (any shape fetch accepts) carries a credential header. */
export function hasCredentialHeaders(headers: any): boolean;
/**
 * Returns the request init for the next hop of a redirect, following the Fetch
 * spec: credentials are dropped when the redirect leaves the current origin, and
 * a 303 (or a 301/302 after POST) becomes a bodiless GET.
 * @param {RequestInit} init
 * @param {number} status
 * @param {URL} from
 * @param {URL} to
 */
export function nextRedirectInit(init: RequestInit, status: number, from: URL, to: URL): {
    body?: BodyInit | null;
    cache?: RequestCache;
    credentials?: RequestCredentials;
    headers?: HeadersInit;
    integrity?: string;
    keepalive?: boolean;
    method?: string;
    mode?: RequestMode;
    priority?: RequestPriority;
    redirect?: RequestRedirect;
    referrer?: string;
    referrerPolicy?: ReferrerPolicy;
    signal?: AbortSignal | null;
    window?: null;
};
