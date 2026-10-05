// HTTP plumbing for the runtime benchmark (issue #54). Every server binds to
// 127.0.0.1 on an OS-assigned port, and the client only ever talks to those
// addresses, so a run is isolated from the network and reproducible: no fixed
// ports, no external hosts, no extra dependencies.
import { createServer } from "node:http";

export function parseCookies(header = "") {
  const cookies = {};
  for (const part of String(header).split(";")) {
    const index = part.indexOf("=");
    if (index > 0) cookies[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return cookies;
}

/** The `name=value` pair a response set, for replaying as a `cookie` header. */
export function cookieOf(headers) {
  const raw = headers.get("set-cookie");
  return raw ? raw.split(";")[0] : null;
}

export async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return null; // malformed JSON: the routes answer 400
  }
}

export function sendJson(res, status, payload, headers = {}) {
  const text = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": String(Buffer.byteLength(text)),
    ...headers
  });
  res.end(text);
}

/** Starts `handler` on 127.0.0.1:0 and returns `{ baseUrl, close }`. */
export async function listen(handler) {
  const server = createServer(handler);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise((resolve) => {
        // fetch() keeps connections alive; drop them so close() can finish.
        server.closeAllConnections?.();
        server.close(resolve);
      })
  };
}

export async function httpRequest(baseUrl, { method = "GET", path = "/", headers = {}, body } = {}) {
  const init = { method, headers: { ...headers } };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const response = await fetch(`${baseUrl}${path}`, init);
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // non-JSON response: `text` is the evidence
  }
  return { status: response.status, headers: response.headers, text, json };
}
