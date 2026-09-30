import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

const ABSOLUTE_URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;
const CREDENTIAL_HEADERS = new Set(["authorization", "x-csrf-token", "cookie"]);

function stripCredentialHeaders(headers = {}) {
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !CREDENTIAL_HEADERS.has(name.toLowerCase())));
}

export class HTTPClient {
  /**
   * @param {{baseUrl?: string, csrfManager?: import('./CSRFTokenManager.js').CSRFTokenManager, tokenProvider?: ()=>Promise<string|null>|string|null, fetchImpl?: typeof fetch, outboundRequestPolicy?: { validateUrl: (url: string) => unknown }, allowedOrigins?: string[]}} [options]
   */
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || "";
    this.csrfManager = options.csrfManager || null;
    this.tokenProvider = options.tokenProvider || null;
    this.fetchImpl = options.fetchImpl || ((...args) => fetch(...args));
    this.outboundRequestPolicy = options.outboundRequestPolicy || null;
    this.allowedOrigins = new Set(options.allowedOrigins || []);
    this.requestInterceptors = [];
    this.responseInterceptors = [];
  }

  addRequestInterceptor(interceptor) {
    this.requestInterceptors.push(interceptor);
  }

  addResponseInterceptor(interceptor) {
    this.responseInterceptors.push(interceptor);
  }

  // Relative URLs always resolve under baseUrl/the current origin, so only an
  // absolute request URL can point somewhere else and needs an origin check.
  _isCredentialSafeOrigin(requestUrl) {
    if (!ABSOLUTE_URL_PATTERN.test(requestUrl)) return true;

    let targetOrigin;
    try {
      targetOrigin = new URL(requestUrl).origin;
    } catch {
      return false;
    }

    if (this.allowedOrigins.has(targetOrigin)) return true;

    if (this.baseUrl) {
      try {
        return new URL(this.baseUrl).origin === targetOrigin;
      } catch {
        return false;
      }
    }

    return false;
  }

  async request(url, options = {}) {
    let config = {
      ...options,
      headers: { ...(options.headers || {}) }
    };

    const requestUrl = ABSOLUTE_URL_PATTERN.test(url) ? url : `${this.baseUrl}${url}`;

    if (this.csrfManager || this.tokenProvider) {
      if (!this._isCredentialSafeOrigin(requestUrl)) {
        throw new SecurityError(
          SecurityErrorCode.CREDENTIAL_LEAK_BLOCKED,
          "Refusing to attach Authorization/CSRF credentials to a cross-origin request",
          { url: requestUrl }
        );
      }
    }

    if (this.csrfManager) {
      config.headers = this.csrfManager.attach(config.headers);
    }

    if (this.tokenProvider) {
      const token = await this.tokenProvider();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
    }

    for (const interceptor of this.requestInterceptors) {
      config = (await interceptor(config)) || config;
    }

    const response = this.outboundRequestPolicy
      ? await this._fetchWithPolicy(requestUrl, config)
      : await this.fetchImpl(requestUrl, config);
    const normalized = {
      ok: response.ok,
      status: response.status,
      headers: response.headers,
      data: null,
      error: null,
      raw: response
    };

    try {
      normalized.data = await response.clone().json();
    } catch {
      normalized.data = await response.text();
    }

    if (!response.ok) {
      normalized.error = new SecurityError(SecurityErrorCode.INVALID_INPUT, "HTTP request failed", {
        status: response.status,
        body: normalized.data
      });
    }

    for (const interceptor of this.responseInterceptors) {
      await interceptor(normalized);
    }

    return normalized;
  }

  // Follows redirects manually so every hop passes the outbound policy, and
  // drops credentials when a redirect leaves the original origin.
  async _fetchWithPolicy(requestUrl, config) {
    const policy = this.outboundRequestPolicy;
    const maxHops = Number.isInteger(policy.maxRedirectHops) ? policy.maxRedirectHops : 3;
    let target = requestUrl;
    let init = { ...config, redirect: "manual" };

    for (let hop = 0; hop <= maxHops; hop++) {
      if (typeof policy.assertResolvedSafe === "function") {
        await policy.assertResolvedSafe(target);
      } else {
        policy.validateUrl(target);
      }

      const response = await this.fetchImpl(target, init);
      const isRedirect = response.status >= 300 && response.status < 400;
      const location = isRedirect ? response.headers?.get?.("location") : null;
      if (!location) return response;

      const next = new URL(location, target);
      if (next.origin !== new URL(target).origin) {
        init = { ...init, headers: stripCredentialHeaders(init.headers) };
      }
      const method = String(init.method || "GET").toUpperCase();
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === "POST")) {
        init = { ...init, method: "GET" };
        delete init.body;
      }
      target = next.toString();
    }

    throw new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Redirect hop limit exceeded", { max: maxHops });
  }
}