export class SSRFGuard {
    /**
     * @param {{allowHosts?: string[] | Iterable<string>, allowProtocols?: string[] | Iterable<string>, maxRedirectHops?: number, resolveHost?: (hostname: string) => Promise<string[]>}} [options]
     */
    constructor({ allowHosts, allowProtocols, maxRedirectHops, resolveHost }?: {
        allowHosts?: string[] | Iterable<string>;
        allowProtocols?: string[] | Iterable<string>;
        maxRedirectHops?: number;
        resolveHost?: (hostname: string) => Promise<string[]>;
    });
    allowHosts: string[] | null;
    allowProtocols: Set<string>;
    maxRedirectHops: number;
    resolveHost: typeof defaultResolveHost;
    isHostAllowed(hostname: string): boolean;
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
     * Accepts optional pinned address or host-to-address mapping.
     */
    createSafeLookup(pinned?: string | Record<string, string | string[]> | Map<string, string | string[]> | null): (hostname: any, options: any, callback: any) => void;
    /**
     * Returns a lookup function pinned to the exact validated IP address(es).
     */
    createPinnedLookup(hostnameOrMap: string | Record<string, string | string[]> | Map<string, string | string[]>, ip?: string): (hostname: any, options: any, callback: any) => void;
    validateRedirectChain(chain: any): boolean;
}

export interface IsAllowedUrlOptions {
    allowHosts?: string[] | Iterable<string>;
    allowProtocols?: string[] | Iterable<string>;
    allowSchemes?: string[] | Iterable<string>;
}

/**
 * Synchronously checks whether a URL is permitted according to SSRF policies.
 * Parses the URL with the standard URL parser, normalizes hostname case, trailing dots,
 * and IDN/IDNA representations, and performs safe exact hostname matching (e.g. `*.domain.com`).
 * Enforces HTTPS by default; permits other schemes only through explicit opt-in.
 * Blocks private, loopback, link-local, and reserved IP/host targets.
 */
export function isAllowedUrl(
    url: string | URL,
    options?: IsAllowedUrlOptions | string[] | Iterable<string> | SSRFGuard
): boolean;

export function normalizeHostname(hostname: string): string;
export function matchHostAllowlist(hostname: string, allowHosts: string[] | Iterable<string>): boolean;

declare function defaultResolveHost(hostname: any): Promise<any>;
export {};
