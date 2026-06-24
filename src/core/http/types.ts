/**
 * HTTP Client Types
 */

export interface HTTPConfig {
  baseURL: string;
  timeout?: number;
  headers?: Record<string, string>;
}

export interface HTTPResponse<T = any> {
  status: number;
  data: T;
  headers: Record<string, string>;
}

export interface HTTPRequest {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  url: string;
  headers?: Record<string, string>;
  data?: any;
}

export type RequestInterceptor = (request: HTTPRequest) => HTTPRequest | Promise<HTTPRequest>;
export type ResponseInterceptor = <T>(response: HTTPResponse<T>) => HTTPResponse<T> | Promise<HTTPResponse<T>>;
export type ErrorInterceptor = (error: Error) => void | Promise<void>;
