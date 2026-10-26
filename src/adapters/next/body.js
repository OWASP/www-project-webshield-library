// Same default as Express's `express.json()`.
export const DEFAULT_BODY_LIMIT = 100 * 1024;

// application/json and structured suffixes such as application/merge-patch+json.
const JSON_CONTENT_TYPE = /^application\/(?:[\w.+-]+\+)?json\s*(?:;|$)/i;

// Follows the `http-errors` convention (`status` + `expose`), which
// `toErrorResponse()` maps to a 4xx with the message instead of a 500.
function clientError(status, message) {
  return Object.assign(new Error(message), { status, expose: true });
}

/**
 * Reads the body as UTF-8 text, stopping as soon as it passes `limit` bytes,
 * so an oversized upload is never buffered in full. Route handlers have no
 * body size limit of their own.
 */
async function readText(request, limit) {
  const declared = Number(request.headers.get("content-length"));
  if (declared > limit) throw clientError(413, "Request body too large");

  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw clientError(413, "Request body too large");
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

/**
 * Parses a JSON request body. Returns `undefined` for an empty body, and
 * throws 415 for a non-JSON content type, 413 over `limit` bytes and 400 for
 * malformed JSON.
 * @param {Request} request
 * @param {{limit?: number}} [options]
 * @returns {Promise<unknown>}
 */
export async function readJsonBody(request, { limit = DEFAULT_BODY_LIMIT } = {}) {
  if (!request.body) return undefined;
  const text = await readText(request, limit);
  if (text === "") return undefined;
  if (!JSON_CONTENT_TYPE.test(request.headers.get("content-type") || "")) {
    throw clientError(415, "Expected a JSON request body");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw clientError(400, "Malformed JSON request body");
  }
}
