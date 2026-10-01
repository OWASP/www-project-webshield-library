/**
 * Hook that returns a SafeFetcher enforcing SSRF policy. The instance is kept
 * across renders while `config` is structurally equal (functions inside it, such
 * as `resolveHost`, are compared by identity).
 */
export function useSafeFetcher(config: {}, fetchImpl: any): any;
