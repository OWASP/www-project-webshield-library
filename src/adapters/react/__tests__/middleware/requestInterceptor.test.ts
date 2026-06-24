import { createInterceptorChain, RequestInterceptor, ResponseInterceptor } from '../../middleware/requestInterceptor';

function makeMockFetch(status = 200): jest.Mock {
  return jest.fn().mockResolvedValue(
    new Response(JSON.stringify({ ok: true }), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })
  );
}

describe('createInterceptorChain', () => {
  it('calls the underlying fetch', async () => {
    const mockFetch = makeMockFetch();
    const chain = createInterceptorChain(mockFetch as any);
    await chain.fetch('https://example.com/api');
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('applies request interceptors in order', async () => {
    const mockFetch = makeMockFetch();
    const chain = createInterceptorChain(mockFetch as any);
    const order: number[] = [];

    const i1: RequestInterceptor = async (_input, init) => { order.push(1); return init; };
    const i2: RequestInterceptor = async (_input, init) => { order.push(2); return init; };
    chain.addRequestInterceptor(i1);
    chain.addRequestInterceptor(i2);

    await chain.fetch('https://example.com/api');
    expect(order).toEqual([1, 2]);
  });

  it('allows request interceptor to add headers', async () => {
    const mockFetch = makeMockFetch();
    const chain = createInterceptorChain(mockFetch as any);

    const interceptor: RequestInterceptor = async (_input, init) => ({
      ...init,
      headers: new Headers({ Authorization: 'Bearer test-token' }),
    });
    chain.addRequestInterceptor(interceptor);

    await chain.fetch('https://example.com/api', { method: 'GET' });

    const [, calledInit] = mockFetch.mock.calls[0];
    const headers = new Headers(calledInit.headers);
    expect(headers.get('Authorization')).toBe('Bearer test-token');
  });

  it('applies response interceptors', async () => {
    const mockFetch = makeMockFetch();
    const chain = createInterceptorChain(mockFetch as any);
    let intercepted = false;

    const ri: ResponseInterceptor = async (res) => { intercepted = true; return res; };
    chain.addResponseInterceptor(ri);

    await chain.fetch('https://example.com/api');
    expect(intercepted).toBe(true);
  });

  it('removes request interceptor via returned cleanup', async () => {
    const mockFetch = makeMockFetch();
    const chain = createInterceptorChain(mockFetch as any);
    let called = false;

    const interceptor: RequestInterceptor = async (_input, init) => { called = true; return init; };
    const remove = chain.addRequestInterceptor(interceptor);

    remove();
    await chain.fetch('https://example.com/api');
    expect(called).toBe(false);
  });
});

