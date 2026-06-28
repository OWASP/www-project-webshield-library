import { SecurityError, SecurityErrorCode } from "../error/SecurityError.js";

export class HTTPClient {
  /**
   * @param {{baseUrl?: string, csrfManager?: import('./CSRFTokenManager.js').CSRFTokenManager, tokenProvider?: ()=>Promise<string|null>|string|null, fetchImpl?: typeof fetch, outboundRequestPolicy?: { validateUrl: (url: string) => unknown }}} [options]
   */
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || "";
    this.csrfManager = options.csrfManager || null;
    this.tokenProvider = options.tokenProvider || null;
    this.fetchImpl = options.fetchImpl || fetch;
    this.outboundRequestPolicy = options.outboundRequestPolicy || null;
    this.requestInterceptors = [];
    this.responseInterceptors = [];
  }

  addRequestInterceptor(interceptor) {
    this.requestInterceptors.push(interceptor);
  }

  addResponseInterceptor(interceptor) {
    this.responseInterceptors.push(interceptor);
  }

  async request(url, options = {}) {
    let config = {
      ...options,
      headers: {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        ...(options.headers || {})
      }
    };

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

    const requestUrl = `${this.baseUrl}${url}`;
    if (this.outboundRequestPolicy) {
      this.outboundRequestPolicy.validateUrl(requestUrl);
    }

    const response = await this.fetchImpl(requestUrl, config);
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
}