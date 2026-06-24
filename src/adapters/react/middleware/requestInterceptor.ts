/**
 * Composable request interceptor utilities for augmenting fetch requests
 * with auth tokens, CSRF headers, logging, etc.
 */

export type RequestInterceptor = (
  input: RequestInfo | URL,
  init: RequestInit
) => RequestInit | Promise<RequestInit>;

export type ResponseInterceptor = (response: Response) => Response | Promise<Response>;

export interface InterceptorChain {
  addRequestInterceptor(fn: RequestInterceptor): () => void;
  addResponseInterceptor(fn: ResponseInterceptor): () => void;
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

/**
 * Creates a composable fetch client with pluggable request and response
 * interceptors — without monkey-patching the global `fetch`.
 */
export function createInterceptorChain(
  baseFetch: typeof fetch = globalThis.fetch
): InterceptorChain {
  const requestInterceptors: RequestInterceptor[] = [];
  const responseInterceptors: ResponseInterceptor[] = [];

  function addRequestInterceptor(fn: RequestInterceptor): () => void {
    requestInterceptors.push(fn);
    return () => {
      const idx = requestInterceptors.indexOf(fn);
      if (idx !== -1) requestInterceptors.splice(idx, 1);
    };
  }

  function addResponseInterceptor(fn: ResponseInterceptor): () => void {
    responseInterceptors.push(fn);
    return () => {
      const idx = responseInterceptors.indexOf(fn);
      if (idx !== -1) responseInterceptors.splice(idx, 1);
    };
  }

  async function fetchWithInterceptors(
    input: RequestInfo | URL,
    init: RequestInit = {}
  ): Promise<Response> {
    // Run request interceptors in order
    let current = init;
    for (const interceptor of requestInterceptors) {
      current = await interceptor(input, current);
    }

    let response = await baseFetch(input, current);

    // Run response interceptors in order
    for (const interceptor of responseInterceptors) {
      response = await interceptor(response);
    }

    return response;
  }

  return {
    addRequestInterceptor,
    addResponseInterceptor,
    fetch: fetchWithInterceptors,
  };
}
