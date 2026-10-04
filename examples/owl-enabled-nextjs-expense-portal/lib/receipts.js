import { createHash } from "node:crypto";
import { SecurityError, SecurityErrorCode } from "@owasp-webshield/core";

export const MAX_RECEIPT_BYTES = 2 * 1024 * 1024;

// The file types a receipt may be, recognized by their first bytes. The
// Content-Type the remote server sends is only a claim; the bytes decide.
const SIGNATURES = [
  { type: "application/pdf", extension: "pdf", bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] }, // %PDF-
  { type: "image/png", extension: "png", bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { type: "image/jpeg", extension: "jpg", bytes: [0xff, 0xd8, 0xff] }
];

export function sniffType(bytes) {
  return SIGNATURES.find(({ bytes: signature }) => signature.every((byte, i) => bytes[i] === byte)) || null;
}

function rejected(message) {
  return new SecurityError(SecurityErrorCode.INVALID_INPUT, message, { errors: [{ field: "url", code: "receipt", message }] });
}

async function readLimited(response, limit) {
  if (Number(response.headers.get("content-length")) > limit) throw rejected("The receipt is larger than 2 MB");
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw rejected("The receipt is larger than 2 MB");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks, size);
}

/**
 * A10: downloads a receipt from a user-supplied URL. `withOwl({ outboundUrl })`
 * has already refused private, loopback and metadata addresses; `fetcher` is
 * a `SafeFetcher`, which re-checks every redirect hop and, with its pinned-DNS
 * dispatcher, connects only to the address it checked.
 *
 * The response is read with a size limit and a timeout, and kept only if its
 * bytes are really a PDF, PNG or JPEG.
 */
export async function downloadReceipt(url, { fetcher, timeoutMs = 5000, limit = MAX_RECEIPT_BYTES }) {
  let response;
  try {
    response = await fetcher.fetch(url, { headers: { Accept: "application/pdf,image/png,image/jpeg" }, signal: AbortSignal.timeout(timeoutMs) });
  } catch (error) {
    if (error?.code === "SSRF_BLOCKED") throw error; // a redirect to a blocked target
    throw rejected("The receipt couldn't be downloaded");
  }
  if (!response.ok || !response.body) throw rejected(`The receipt server answered ${response.status}`);

  const bytes = await readLimited(response, limit);
  const kind = sniffType(bytes);
  if (!kind) throw rejected("A receipt must be a PDF, PNG or JPEG file");

  return {
    contentType: kind.type,
    extension: kind.extension,
    size: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    sourceHost: new URL(url).host,
    bytes
  };
}
