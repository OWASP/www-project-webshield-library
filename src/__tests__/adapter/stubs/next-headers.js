// Stand-in for next/headers (see jest.config.js): `headers()` returns whatever
// the test last passed to `setRequestHeaders()`.
let current = new Headers();

export function setRequestHeaders(init) {
  current = new Headers(init);
}

export async function headers() {
  return current;
}
