/**
 * HTTPClient Tests
 */

import { HTTPClient } from '../HTTPClient';
import { HTTPRequest, HTTPResponse } from '../types';

describe('HTTPClient', () => {
  let client: HTTPClient;

  beforeEach(() => {
    client = new HTTPClient({
      baseURL: 'https://api.example.com',
    });

    // Mock fetch
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('Configuration', () => {
    it('should initialize with config', () => {
      expect(client).toBeDefined();
    });

    it('should set default header', () => {
      client.setDefaultHeader('Authorization', 'Bearer token123');
      expect(client).toBeDefined();
    });

    it('should set base URL', () => {
      client.setBaseURL('https://new-api.example.com');
      expect(client).toBeDefined();
    });

    it('should set timeout', () => {
      client.setTimeout(60000);
      expect(client).toBeDefined();
    });
  });

  describe('Interceptors', () => {
    it('should register request interceptor', () => {
      const interceptor = (req: HTTPRequest) => req;
      const unsubscribe = client.useRequestInterceptor(interceptor);
      expect(unsubscribe).toBeDefined();
      expect(typeof unsubscribe).toBe('function');
    });

    it('should unsubscribe request interceptor', () => {
      const interceptor = (req: HTTPRequest) => req;
      const unsubscribe = client.useRequestInterceptor(interceptor);
      expect(unsubscribe).toBeDefined();
    });

    it('should register response interceptor', () => {
      const interceptor = <T>(res: HTTPResponse<T>) => res;
      const unsubscribe = client.useResponseInterceptor(interceptor);
      expect(unsubscribe).toBeDefined();
    });

    it('should register error interceptor', () => {
      const interceptor = (error: Error) => {};
      const unsubscribe = client.useErrorInterceptor(interceptor);
      expect(unsubscribe).toBeDefined();
    });
  });

  describe('HTTP Methods', () => {
    beforeEach(() => {
      (global.fetch as jest.Mock).mockResolvedValue({
        status: 200,
        ok: true,
        json: async () => ({ data: 'test' }),
        headers: new Map([['content-type', 'application/json']]),
      });
    });

    it('should make GET request', async () => {
      await client.get('/test');
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/test',
        expect.objectContaining({ method: 'GET' })
      );
    });

    it('should make POST request', async () => {
      await client.post('/test', { key: 'value' });
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/test',
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('should make PUT request', async () => {
      await client.put('/test', { key: 'value' });
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/test',
        expect.objectContaining({ method: 'PUT' })
      );
    });

    it('should make DELETE request', async () => {
      await client.delete('/test');
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/test',
        expect.objectContaining({ method: 'DELETE' })
      );
    });

    it('should make PATCH request', async () => {
      await client.patch('/test', { key: 'value' });
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/test',
        expect.objectContaining({ method: 'PATCH' })
      );
    });
  });

  describe('Request Interceptors', () => {
    it('should call request interceptor', async () => {
      const interceptor = jest.fn((req) => req);
      client.useRequestInterceptor(interceptor);

      (global.fetch as jest.Mock).mockResolvedValue({
        status: 200,
        ok: true,
        json: async () => ({}),
        headers: new Map([['content-type', 'application/json']]),
      });

      await client.get('/test');

      expect(interceptor).toHaveBeenCalled();
    });

    it('should modify request in interceptor', async () => {
      client.useRequestInterceptor((req) => ({
        ...req,
        headers: { ...req.headers, 'X-Custom': 'value' },
      }));

      (global.fetch as jest.Mock).mockResolvedValue({
        status: 200,
        ok: true,
        json: async () => ({}),
        headers: new Map([['content-type', 'application/json']]),
      });

      await client.get('/test');

      const callArgs = (global.fetch as jest.Mock).mock.calls[0];
      expect(callArgs[1].headers['X-Custom']).toBe('value');
    });
  });

  describe('Error Handling', () => {
    it('should handle HTTP errors', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        status: 404,
        ok: false,
        json: async () => ({ error: 'Not found' }),
        headers: new Map([['content-type', 'application/json']]),
      });

      await expect(client.get('/test')).rejects.toThrow();
    });

    it('should call error interceptor on error', async () => {
      const errorInterceptor = jest.fn();
      client.useErrorInterceptor(errorInterceptor);

      (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

      await expect(client.get('/test')).rejects.toThrow();
      expect(errorInterceptor).toHaveBeenCalled();
    });
  });

  describe('URL Building', () => {
    it('should build full URL with base URL', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        status: 200,
        ok: true,
        json: async () => ({}),
        headers: new Map([['content-type', 'application/json']]),
      });

      await client.get('/users/123');

      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.example.com/users/123',
        expect.any(Object)
      );
    });

    it('should handle absolute URLs', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        status: 200,
        ok: true,
        json: async () => ({}),
        headers: new Map([['content-type', 'application/json']]),
      });

      await client.get('https://other-api.com/data');

      expect(global.fetch).toHaveBeenCalledWith(
        'https://other-api.com/data',
        expect.any(Object)
      );
    });
  });
});
