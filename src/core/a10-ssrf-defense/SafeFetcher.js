import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";
import { nextRedirectInit } from "./redirect.js";

export class SafeFetcher {
  /**
   * Without a `dispatcher`, the DNS check and the actual connection resolve the
   * host separately, so a rebinding DNS server can still race them. In Node, pass
   * `new Agent({ connect: { lookup: guard.createSafeLookup() } })` from undici.
   * @param {{guard: import('./SSRFGuard.js').SSRFGuard, fetchImpl?: typeof fetch, dispatcher?: unknown}} options
   */
  constructor(options) {
    this.guard = options.guard;
    this.fetchImpl = options.fetchImpl || ((...args) => fetch(...args));
    this.dispatcher = options.dispatcher || null;
  }

  // Follows redirects manually so every hop is re-validated (DNS-resolved) before
  // being requested, closing the SSRF bypass where fetch auto-follows an
  // attacker-controlled redirect to a private/internal target. Credentials are
  // dropped when a redirect leaves the current origin, as native fetch does.
  async fetch(url, options = {}) {
    let target = url;
    let init = { ...options, redirect: "manual" };
    if (this.dispatcher) init.dispatcher = this.dispatcher;

    for (let hop = 0; hop <= this.guard.maxRedirectHops; hop++) {
      const validated = await this.guard.assertResolvedSafe(target);
      const response = await this.fetchImpl(validated.toString(), init);

      const isRedirect = response.status >= 300 && response.status < 400;
      const location = isRedirect ? response.headers?.get?.("location") : null;
      if (!location) {
        return response;
      }
      const next = new URL(location, validated);
      init = nextRedirectInit(init, response.status, validated, next);
      target = next.toString();
    }

    throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Redirect hop limit exceeded", {
      max: this.guard.maxRedirectHops
    });
  }
}
