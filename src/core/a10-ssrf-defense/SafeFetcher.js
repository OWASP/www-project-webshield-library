import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

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
  // attacker-controlled redirect to a private/internal target.
  async fetch(url, options = {}) {
    let target = url;

    for (let hop = 0; hop <= this.guard.maxRedirectHops; hop++) {
      const validated = await this.guard.assertResolvedSafe(target);
      const init = { ...options, redirect: "manual" };
      if (this.dispatcher) init.dispatcher = this.dispatcher;
      const response = await this.fetchImpl(validated.toString(), init);

      const isRedirect = response.status >= 300 && response.status < 400;
      const location = isRedirect ? response.headers?.get?.("location") : null;
      if (!location) {
        return response;
      }
      target = new URL(location, validated).toString();
    }

    throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Redirect hop limit exceeded", {
      max: this.guard.maxRedirectHops
    });
  }
}