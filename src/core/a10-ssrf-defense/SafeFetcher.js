export class SafeFetcher {
  /**
   * @param {{guard: import('./SSRFGuard.js').SSRFGuard, fetchImpl?: typeof fetch}} options
   */
  constructor(options) {
    this.guard = options.guard;
    this.fetchImpl = options.fetchImpl || fetch;
  }

  async fetch(url, options = {}) {
    this.guard.validateUrl(url);
    return this.fetchImpl(url, options);
  }
}