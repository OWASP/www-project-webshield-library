import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";
import { hasCredentialHeaders, nextRedirectInit } from "../a10-ssrf-defense/redirect.js";

const ABSOLUTE_URL_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;

// Outside a browser there is no page to resolve relative URLs against, so this
// placeholder stands in for "the page's own origin".
const NO_PAGE_BASE = "http://owl.invalid/";

/**
 * The caller's headers as a plain object, whichever shape fetch() accepts: a plain
 * object, [name, value] pairs or a Headers instance. Spreading the last two (the
 * obvious `{ ...headers }`) silently loses every header: a Headers instance has no
 * own properties, and pairs become numeric keys.
 */
function toHeaderObject(headers) {
  if (!headers) return {};
  if (typeof headers.forEach === "function" && typeof headers.get === "function") {
    const plain = {};
    headers.forEach((value, name) => {
      plain[name] = value;
    });
    return plain;
  }
  if (Array.isArray(headers)) return Object.fromEntries(headers);
  return { ...headers };
}

// fetch() resolves relative URLs against the document base URL in browsers.
function pageContext() {
  return {
    base: globalThis.document?.baseURI || globalThis.location?.href || NO_PAGE_BASE,
    origin: globalThis.location?.origin || new URL(NO_PAGE_BASE).origin
  };
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

  // Resolves the URL exactly as fetch() will rather than pattern-matching the raw
  // string: " https://evil", "//evil" and "/\evil" all look relative but resolve to
  // another origin. Credentials may only go to baseUrl's origin (the page's origin
  // when baseUrl is empty or relative) or an explicitly allowlisted origin.
  _isCredentialSafeOrigin(requestUrl) {
    const page = pageContext();
    let target;
    try {
      target = new URL(requestUrl, page.base);
    } catch {
      return false;
    }
    if (target.origin === "null") return false; // opaque origins (data:, file:, ...) never match

    if (this.allowedOrigins.has(target.origin)) return true;

    let ownOrigin;
    try {
      ownOrigin = new URL(this.baseUrl).origin;
    } catch {
      ownOrigin = page.origin; // empty or relative baseUrl
    }
    return target.origin === ownOrigin;
  }

  async request(url, options = {}) {
    let config = {
      ...options,
      headers: toHeaderObject(options.headers)
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

    // fetch keeps custom headers such as X-CSRF-Token when it follows a redirect to
    // another origin, so credentialed requests follow redirects themselves unless
    // the caller chose a `redirect` mode explicitly.
    let response;
    if (this.outboundRequestPolicy) {
      response = await this._followRedirects(requestUrl, config, this.outboundRequestPolicy);
    } else if (config.redirect === undefined && hasCredentialHeaders(config.headers)) {
      response = await this._followRedirects(requestUrl, config, null);
    } else {
      response = await this.fetchImpl(requestUrl, config);
    }
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

  // Follows redirects manually: every hop passes the outbound policy (when there is
  // one), and credentials are dropped when a redirect leaves the current origin.
  async _followRedirects(requestUrl, config, policy) {
    const maxHops = policy ? (Number.isInteger(policy.maxRedirectHops) ? policy.maxRedirectHops : 3) : 20;
    let target = requestUrl;
    let init = { ...config, redirect: "manual" };

    for (let hop = 0; hop <= maxHops; hop++) {
      if (typeof policy?.assertResolvedSafe === "function") {
        await policy.assertResolvedSafe(target);
      } else if (policy) {
        policy.validateUrl(target);
      }

      const response = await this.fetchImpl(target, init);
      // Browsers hide the Location of a manual redirect (status 0, type "opaqueredirect"),
      // so the next hop can't be checked; refuse it instead of returning a blank response.
      if (response.type === "opaqueredirect") {
        throw policy
          ? new SecurityError(
              SecurityErrorCode.SSRF_BLOCKED,
              "Redirect cannot be validated in this runtime (opaque redirect); request the final URL directly",
              { url: target }
            )
          : new SecurityError(
              SecurityErrorCode.CREDENTIAL_LEAK_BLOCKED,
              'Credentialed request was redirected to a target that cannot be checked in this runtime; request the final URL directly, or pass redirect: "follow" to accept forwarding the credentials',
              { url: target }
            );
      }
      const isRedirect = response.status >= 300 && response.status < 400;
      const location = isRedirect ? response.headers?.get?.("location") : null;
      if (!location) return response;

      const base = new URL(target, pageContext().base);
      const next = new URL(location, base);
      init = nextRedirectInit(init, response.status, base, next);
      target = next.toString();
    }

    throw policy
      ? new SecurityError(SecurityErrorCode.SSRF_BLOCKED, "Redirect hop limit exceeded", { max: maxHops })
      : new SecurityError(SecurityErrorCode.INVALID_INPUT, "Redirect hop limit exceeded", { max: maxHops });
  }
}