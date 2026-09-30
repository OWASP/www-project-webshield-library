export class SafeFetcher {
    /**
     * Without a `dispatcher`, the DNS check and the actual connection resolve the
     * host separately, so a rebinding DNS server can still race them. In Node, pass
     * `new Agent({ connect: { lookup: guard.createSafeLookup() } })` from undici.
     * @param {{guard: import('./SSRFGuard.js').SSRFGuard, fetchImpl?: typeof fetch, dispatcher?: unknown}} options
     */
    constructor(options: {
        guard: import("./SSRFGuard.js").SSRFGuard;
        fetchImpl?: typeof fetch;
        dispatcher?: unknown;
    });
    guard: import("./SSRFGuard.js").SSRFGuard;
    fetchImpl: (...args: any[]) => Promise<Response>;
    dispatcher: unknown;
    fetch(url: any, options?: {}): Promise<Response>;
}
