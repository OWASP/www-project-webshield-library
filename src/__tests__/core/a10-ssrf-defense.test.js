import { describe, expect, jest, test } from "@jest/globals";
import { SSRFGuard, SafeFetcher } from "../../core/a10-ssrf-defense/index.js";

describe("A10 ssrf defense", () => {
  test("blocks private targets and validates redirect chain", () => {
    const guard = new SSRFGuard({ maxRedirectHops: 2 });
    expect(() => guard.validateUrl("http://127.0.0.1/internal")).toThrow();
    expect(() => guard.validateRedirectChain(["https://a.com", "https://b.com", "https://c.com"])).toThrow();
  });

  test("blocks unsupported protocols", () => {
    const guard = new SSRFGuard({ allowProtocols: ["https:"] });
    expect(() => guard.validateUrl("ftp://example.com/archive")).toThrow();
  });

  test("safe fetcher validates before calling fetch", async () => {
    const fetchImpl = jest.fn(async () => ({ ok: true }));
    const safeFetcher = new SafeFetcher({ guard: new SSRFGuard(), fetchImpl });

    await expect(safeFetcher.fetch("http://127.0.0.1/internal")).rejects.toThrow();
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});