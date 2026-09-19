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

  test("blocks obfuscated loopback and metadata addresses missed by the old regex list", () => {
    const guard = new SSRFGuard();
    expect(() => guard.validateUrl("http://[::ffff:169.254.169.254]/latest/meta-data/")).toThrow();
    expect(() => guard.validateUrl("http://[0:0:0:0:0:0:0:1]:6379/")).toThrow();
    expect(() => guard.validateUrl("http://0.0.0.0:8080/admin")).toThrow();
  });

  test("assertResolvedSafe blocks a hostname that resolves to a private address (DNS rebinding)", async () => {
    const guard = new SSRFGuard({ resolveHost: async () => ["127.0.0.1"] });
    await expect(guard.assertResolvedSafe("http://attacker-rebind.example/")).rejects.toThrow();
  });

  test("assertResolvedSafe allows a hostname that resolves to a public address", async () => {
    const guard = new SSRFGuard({ resolveHost: async () => ["93.184.216.34"] });
    await expect(guard.assertResolvedSafe("https://example.com/data")).resolves.toBeInstanceOf(URL);
  });

  test("safe fetcher re-validates redirect targets instead of following them blindly", async () => {
    const guard = new SSRFGuard({ resolveHost: async () => ["93.184.216.34"] });
    const fetchImpl = jest.fn(async () => ({
      status: 302,
      headers: { get: (key) => (key === "location" ? "http://169.254.169.254/latest/meta-data/" : null) },
      ok: false
    }));
    const safeFetcher = new SafeFetcher({ guard, fetchImpl });

    await expect(safeFetcher.fetch("https://example.com/redirect")).rejects.toThrow();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});