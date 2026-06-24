import '@testing-library/jest-dom';

// Polyfill Response for jsdom (jsdom 20 doesn't expose the Fetch API globals)
if (typeof Response === 'undefined') {
  class MockResponse {
    private _body: string;
    readonly status: number;
    readonly ok: boolean;
    readonly headers: Record<string, string>;

    constructor(body: string | null = null, init: { status?: number; headers?: Record<string, string> } = {}) {
      this._body = body ?? '';
      this.status = init.status ?? 200;
      this.ok = this.status >= 200 && this.status < 300;
      this.headers = init.headers ?? {};
    }

    async json(): Promise<unknown> {
      return JSON.parse(this._body);
    }

    async text(): Promise<string> {
      return this._body;
    }
  }

  (global as unknown as Record<string, unknown>)['Response'] = MockResponse;
}
