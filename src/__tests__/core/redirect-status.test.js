import { describe, expect, jest, test } from "@jest/globals";
import { HTTPClient } from "../../core/a08-data-integrity/index.js";
import { SafeFetcher } from "../../core/a10-ssrf-defense/index.js";

const response = (status, location) => ({
  ok: status === 200,
  status,
  headers: new Headers(location ? { location } : {}),
  clone: () => ({ json: async () => ({}) })
});

describe.each(["HTTPClient", "SafeFetcher"])("%s redirect status handling", (kind) => {
  const request = (fetchImpl) => {
    const guard = { maxRedirectHops: 3, assertResolvedSafe: async (url) => new URL(url) };
    if (kind === "SafeFetcher") return new SafeFetcher({ guard, fetchImpl }).fetch("https://example.com/start");
    return new HTTPClient({ outboundRequestPolicy: guard, fetchImpl }).request("https://example.com/start");
  };

  test.each([300, 304, 305, 306, 309, 399])("returns %i without following Location", async (status) => {
    const original = response(status, "/unexpected");
    const fetchImpl = jest.fn().mockResolvedValueOnce(original).mockResolvedValue(response(200));
    const result = await request(fetchImpl);
    expect(result.status).toBe(status);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  test.each([301, 302, 303, 307, 308])("follows %i Location", async (status) => {
    const fetchImpl = jest.fn().mockResolvedValueOnce(response(status, "/next")).mockResolvedValue(response(200));
    const result = await request(fetchImpl);
    expect(result.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(fetchImpl.mock.calls[1][0]).toBe("https://example.com/next");
  });
});
