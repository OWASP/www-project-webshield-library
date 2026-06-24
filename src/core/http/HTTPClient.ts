/**
 * HTTPClient - Framework-agnostic HTTP client
 * Provides request/response interceptor support and event handling
 */

import { HTTPConfig, HTTPResponse, HTTPRequest, RequestInterceptor, ResponseInterceptor, ErrorInterceptor } from './types';

export class HTTPClient {
  private config: HTTPConfig;
  private requestInterceptors: RequestInterceptor[] = [];
  private responseInterceptors: ResponseInterceptor[] = [];
  private errorInterceptors: ErrorInterceptor[] = [];

  constructor(config: HTTPConfig) {
    this.config = {
      timeout: 30000,
      ...config,
    };
  }

  /**
   * Add a request interceptor
   */
  useRequestInterceptor(interceptor: RequestInterceptor): () => void {
    this.requestInterceptors.push(interceptor);
    // Return unsubscribe function
    return () => {
      this.requestInterceptors = this.requestInterceptors.filter((i) => i !== interceptor);
    };
  }

  /**
   * Add a response interceptor
   */
  useResponseInterceptor(interceptor: ResponseInterceptor): () => void {
    this.responseInterceptors.push(interceptor);
    // Return unsubscribe function
    return () => {
      this.responseInterceptors = this.responseInterceptors.filter((i) => i !== interceptor);
    };
  }

  /**
   * Add an error interceptor
   */
  useErrorInterceptor(interceptor: ErrorInterceptor): () => void {
    this.errorInterceptors.push(interceptor);
    // Return unsubscribe function
    return () => {
      this.errorInterceptors = this.errorInterceptors.filter((i) => i !== interceptor);
    };
  }

  /**
   * Perform a GET request
   */
  async get<T>(url: string, headers?: Record<string, string>): Promise<HTTPResponse<T>> {
    return this.request<T>({
      method: 'GET',
      url,
      headers,
    });
  }

  /**
   * Perform a POST request
   */
  async post<T>(url: string, data?: any, headers?: Record<string, string>): Promise<HTTPResponse<T>> {
    return this.request<T>({
      method: 'POST',
      url,
      data,
      headers,
    });
  }

  /**
   * Perform a PUT request
   */
  async put<T>(url: string, data?: any, headers?: Record<string, string>): Promise<HTTPResponse<T>> {
    return this.request<T>({
      method: 'PUT',
      url,
      data,
      headers,
    });
  }

  /**
   * Perform a DELETE request
   */
  async delete<T>(url: string, headers?: Record<string, string>): Promise<HTTPResponse<T>> {
    return this.request<T>({
      method: 'DELETE',
      url,
      headers,
    });
  }

  /**
   * Perform a PATCH request
   */
  async patch<T>(url: string, data?: any, headers?: Record<string, string>): Promise<HTTPResponse<T>> {
    return this.request<T>({
      method: 'PATCH',
      url,
      data,
      headers,
    });
  }

  /**
   * Perform a generic HTTP request
   */
  async request<T = any>(requestConfig: HTTPRequest): Promise<HTTPResponse<T>> {
    try {
      // Process request interceptors
      let request: HTTPRequest = {
        ...requestConfig,
        headers: {
          ...this.config.headers,
          ...requestConfig.headers,
        },
      };

      for (const interceptor of this.requestInterceptors) {
        request = await interceptor(request);
      }

      // Build full URL
      const fullUrl = this.buildURL(request.url);

      // Make the request
      const response = await this.fetchRequest<T>(fullUrl, request);

      // Process response interceptors
      let processedResponse = response;
      for (const interceptor of this.responseInterceptors) {
        processedResponse = await interceptor(processedResponse);
      }

      return processedResponse;
    } catch (error) {
      // Process error interceptors
      const err = error instanceof Error ? error : new Error(String(error));
      for (const interceptor of this.errorInterceptors) {
        await interceptor(err);
      }
      throw err;
    }
  }

  /**
   * Build full URL from base URL and path
   */
  private buildURL(url: string): string {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      return url;
    }

    const baseURL = this.config.baseURL.endsWith('/') 
      ? this.config.baseURL.slice(0, -1) 
      : this.config.baseURL;
    const path = url.startsWith('/') ? url : '/' + url;

    return baseURL + path;
  }

  /**
   * Fetch request using native Fetch API
   */
  private async fetchRequest<T>(url: string, request: HTTPRequest): Promise<HTTPResponse<T>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout || 30000);

    try {
      const fetchResponse = await fetch(url, {
        method: request.method,
        headers: request.headers || {},
        body: request.data ? JSON.stringify(request.data) : undefined,
        signal: controller.signal,
      });

      const contentType = fetchResponse.headers.get('content-type');
      let data: T;

      if (contentType?.includes('application/json')) {
        data = await fetchResponse.json();
      } else {
        data = (await fetchResponse.text()) as any;
      }

      // Convert fetch headers to plain object
      const headers: Record<string, string> = {};
      fetchResponse.headers.forEach((value, key) => {
        headers[key] = value;
      });

      const response: HTTPResponse<T> = {
        status: fetchResponse.status,
        data,
        headers,
      };

      if (!fetchResponse.ok) {
        throw new Error(`HTTP Error: ${fetchResponse.status}`);
      }

      return response;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Set a default header
   */
  setDefaultHeader(key: string, value: string): void {
    this.config.headers = this.config.headers || {};
    this.config.headers[key] = value;
  }

  /**
   * Remove a default header
   */
  removeDefaultHeader(key: string): void {
    if (this.config.headers) {
      delete this.config.headers[key];
    }
  }

  /**
   * Update base URL
   */
  setBaseURL(baseURL: string): void {
    this.config.baseURL = baseURL;
  }

  /**
   * Update timeout
   */
  setTimeout(timeout: number): void {
    this.config.timeout = timeout;
  }
}
