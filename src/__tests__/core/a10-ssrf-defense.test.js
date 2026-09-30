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

  test("safe fetcher passes the pinning dispatcher to every request", async () => {
    const guard = new SSRFGuard({ resolveHost: async () => ["93.184.216.34"] });
    const dispatcher = { id: "pinned" };
    const fetchImpl = jest.fn(async () => ({ status: 200, ok: true, headers: { get: () => null } }));
    await new SafeFetcher({ guard, fetchImpl, dispatcher }).fetch("https://example.com/");
    expect(fetchImpl.mock.calls[0][1].dispatcher).toBe(dispatcher);
  });

  describe("createSafeLookup (connect-time validation)", () => {
    const lookupAsync = (lookup, host, options) =>
      new Promise((resolve, reject) => {
        lookup(host, options, (err, address, family) => (err ? reject(err) : resolve({ address, family })));
      });

    test("rejects a rebinding answer at connect time even after a clean pre-check", async () => {
      const answers = [["93.184.216.34"], ["169.254.169.254"]];
      const guard = new SSRFGuard({ resolveHost: async () => answers.shift() });
      await expect(guard.assertResolvedSafe("http://rebind.example/")).resolves.toBeInstanceOf(URL);
      await expect(lookupAsync(guard.createSafeLookup(), "rebind.example", {})).rejects.toMatchObject({ code: "SSRF_BLOCKED" });
    });

    test("returns the validated address in single and all modes", async () => {
      const guard = new SSRFGuard({ resolveHost: async () => ["93.184.216.34", "2606:2800:220:1::1"] });
      const lookup = guard.createSafeLookup();
      await expect(lookupAsync(lookup, "example.com", {})).resolves.toEqual({ address: "93.184.216.34", family: 4 });
      await expect(lookupAsync(lookup, "example.com", { family: 6 })).resolves.toEqual({ address: "2606:2800:220:1::1", family: 6 });
      const all = await lookupAsync(lookup, "example.com", { all: true });
      expect(all.address).toHaveLength(2);
    });

    test("blocks when any resolved address is private", async () => {
      const guard = new SSRFGuard({ resolveHost: async () => ["93.184.216.34", "10.0.0.5"] });
      await expect(lookupAsync(guard.createSafeLookup(), "mixed.example", { all: true })).rejects.toThrow();
    });
  });

  describe("redirect handling in SafeFetcher", () => {
    const redirect = (location, status) => ({ status, headers: { get: (k) => (k === "location" ? location : null) } });
    const ok = () => ({ status: 200, ok: true, headers: { get: () => null } });
    const guard = new SSRFGuard({ resolveHost: async () => ["93.184.216.34"] });

    test("drops credentials on a cross-origin redirect and turns a 303 POST into a bodiless GET", async () => {
      const calls = [];
      const responses = [redirect("https://other.example/done", 303), ok()];
      const fetchImpl = async (url, init) => (calls.push({ url, init }), responses.shift());
      await new SafeFetcher({ guard, fetchImpl }).fetch("https://api.example/upload", {
        method: "POST",
        body: "secret-payload",
        headers: { Authorization: "Bearer INTERNAL", Cookie: "sid=1", "Content-Type": "text/plain", "X-Trace": "t1" }
      });
      expect(calls[1].url).toBe("https://other.example/done");
      expect(calls[1].init.method).toBe("GET");
      expect(calls[1].init.body).toBeUndefined();
      expect(calls[1].init.headers).toEqual({ "X-Trace": "t1" });
    });

    test("keeps credentials, method and body on a same-origin 307", async () => {
      const calls = [];
      const responses = [redirect("/v2/upload", 307), ok()];
      const fetchImpl = async (url, init) => (calls.push({ url, init }), responses.shift());
      await new SafeFetcher({ guard, fetchImpl }).fetch("https://api.example/upload", {
        method: "POST",
        body: "data",
        headers: { Authorization: "Bearer INTERNAL" }
      });
      expect(calls[1].url).toBe("https://api.example/v2/upload");
      expect(calls[1].init).toMatchObject({ method: "POST", body: "data", headers: { Authorization: "Bearer INTERNAL" } });
    });

    test.each([
      [301, "POST", "GET"],
      [302, "POST", "GET"],
      [301, "PUT", "PUT"],
      [308, "POST", "POST"]
    ])("status %i with %s continues as %s", async (status, method, expected) => {
      const calls = [];
      const responses = [redirect("https://api.example/next", status), ok()];
      const fetchImpl = async (url, init) => (calls.push(init), responses.shift());
      await new SafeFetcher({ guard, fetchImpl }).fetch("https://api.example/start", { method, body: "x" });
      expect(calls[1].method).toBe(expected);
    });

    test("strips credentials from a Headers instance too", async () => {
      const calls = [];
      const responses = [redirect("https://other.example/", 302), ok()];
      const fetchImpl = async (url, init) => (calls.push(init), responses.shift());
      await new SafeFetcher({ guard, fetchImpl }).fetch("https://api.example/", {
        headers: new Headers({ Authorization: "Bearer INTERNAL", "X-Trace": "t1" })
      });
      expect(calls[1].headers.get("authorization")).toBeNull();
      expect(calls[1].headers.get("x-trace")).toBe("t1");
    });
  });

  test("assertResolvedSafe fails closed when a resolver returns no addresses", async () => {
    for (const answer of [[], undefined, null]) {
      const guard = new SSRFGuard({ resolveHost: async () => answer });
      await expect(guard.assertResolvedSafe("https://internal.corp/")).rejects.toMatchObject({ code: "SSRF_BLOCKED" });
    }
  });

  test("validateUrl blocks more loopback, reserved and multicast forms", () => {
    const guard = new SSRFGuard();
    for (const url of [
      "http://localhost./",
      "http://LOCALHOST../",
      "http://api.localhost/",
      "http://printer.local./",
      "http://[::127.0.0.1]/",
      "http://[ff02::1]/",
      "http://[fec0::1]/",
      "http://[64:ff9b:1::a00:1]/",
      "http://[2002:7f00:1::]/",
      "http://[2002:a9fe:a9fe::]/"
    ]) {
      expect(() => guard.validateUrl(url)).toThrow();
    }
    expect(guard.validateUrl("http://[2002:5db8:d822::]/")).toBeInstanceOf(URL); // 6to4 for 93.184.216.34
    expect(guard.validateUrl("https://example.com/")).toBeInstanceOf(URL);
  });

  test("trailing-dot handling runs in linear time on long runs of dots (no ReDoS)", () => {
    const guard = new SSRFGuard();
    expect(guard.isPrivateHost("localhost...")).toBe(true);
    expect(guard.isPrivateHost("example.com.")).toBe(false);
    const start = performance.now();
    guard.isPrivateHost("a" + ".".repeat(200000) + "b");
    expect(() => guard.validateUrl("http://a" + ".".repeat(200000) + "b/")).not.toThrow();
    expect(performance.now() - start).toBeLessThan(500);
  });
});
