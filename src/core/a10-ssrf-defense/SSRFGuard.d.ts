export class SSRFGuard {
    /**
     * @param {{allowProtocols?: string[], maxRedirectHops?: number, resolveHost?: (hostname: string) => Promise<string[]>}} [options]
     */
    constructor({ allowProtocols, maxRedirectHops, resolveHost }?: {
        allowProtocols?: string[];
        maxRedirectHops?: number;
        resolveHost?: (hostname: string) => Promise<string[]>;
    });
    allowProtocols: Set<string>;
    maxRedirectHops: number;
    resolveHost: typeof defaultResolveHost;
    isPrivateHost(hostname: any): boolean;
    /**
     * Synchronous, literal-value validation: protocol allowlist and hostname/IP
     * pattern checks. Does NOT resolve DNS, so it cannot detect DNS rebinding
     * (a public hostname whose A/AAAA record points at a private address).
     * Prefer `assertResolvedSafe()` before making the actual outbound request.
     */
    validateUrl(input: any): URL;
    /**
     * Resolves the hostname (unless it is already a literal IP) and validates
     * every returned address, closing the DNS-rebinding gap in `validateUrl()`.
     * Must be called immediately before each connection attempt, including
     * every redirect hop, to keep the resolve-then-check window minimal.
     */
    assertResolvedSafe(input: any): Promise<URL>;
    /**
     * Returns a `dns.lookup`-compatible function that rejects private/reserved
     * addresses at socket-connect time. Because the socket connects to exactly the
     * address validated here, this closes the resolve-then-connect (TOCTOU) window
     * that `assertResolvedSafe()` alone cannot. Use it with an undici dispatcher:
     * `new Agent({ connect: { lookup: guard.createSafeLookup() } })`.
     */
    createSafeLookup(): (hostname: any, options: any, callback: any) => void;
    validateRedirectChain(chain: any): boolean;
}
declare function defaultResolveHost(hostname: any): Promise<any>;
export {};
