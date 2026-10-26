/**
 * Validates a caller-supplied URL (a webhook target, an image to import, an
 * OAuth callback to probe) before the server requests it: protocol allowlist,
 * private/loopback/metadata addresses, and a DNS lookup of the host. Throws
 * `INVALID_INPUT` for a value that isn't a URL and `SSRF_BLOCKED` for a
 * forbidden target.
 *
 * This check runs before the request, so a rebinding DNS server can still
 * answer differently when the request is made. Make the request itself with
 * `SafeFetcher` and a dispatcher using `guard.createSafeLookup()`, which also
 * re-checks every redirect.
 *
 * @param {unknown} url
 * @param {{guard?: SSRFGuard}} [options]
 * @returns {Promise<URL>}
 */
export function assertSafeOutboundUrl(url: unknown, { guard }?: {
    guard?: SSRFGuard;
}): Promise<URL>;
import { SSRFGuard } from "@owasp-webshield/core";
