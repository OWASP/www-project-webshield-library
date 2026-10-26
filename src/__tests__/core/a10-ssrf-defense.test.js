import { describe, expect, jest, test } from "@jest/globals";
import { SSRFGuard, SafeFetcher, isAllowedUrl, matchHostAllowlist, normalizeHostname } from "../../core/a10-ssrf-defense/index.js";

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

  describe("issue #93: allowHosts and isAllowedUrl", () => {
    test("allowHosts allows exact matching host and denies non-matching hosts", () => {
      const guard = new SSRFGuard({ allowHosts: ["hooks.example.com"] });
      expect(guard.validateUrl("https://hooks.example.com/webhook")).toBeInstanceOf(URL);
      expect(() => guard.validateUrl("https://evil.example.com/")).toThrow();
      expect(() => guard.validateUrl("https://example.com/")).toThrow();

      expect(isAllowedUrl("https://hooks.example.com/webhook", { allowHosts: ["hooks.example.com"] })).toBe(true);
      expect(isAllowedUrl("https://other.example.com/", { allowHosts: ["hooks.example.com"] })).toBe(false);
    });

    test("allowHosts with multiple allowed hosts", () => {
      const guard = new SSRFGuard({ allowHosts: ["api.example.com", "service.example.org"] });
      expect(guard.validateUrl("https://api.example.com/v1")).toBeInstanceOf(URL);
      expect(guard.validateUrl("https://service.example.org/v2")).toBeInstanceOf(URL);
      expect(() => guard.validateUrl("https://unrelated.com/")).toThrow();
    });

    test("empty allowHosts denies all hosts", () => {
      const guard = new SSRFGuard({ allowHosts: [] });
      expect(() => guard.validateUrl("https://example.com/")).toThrow();
      expect(() => guard.validateUrl("https://google.com/")).toThrow();
      expect(isAllowedUrl("https://example.com/", { allowHosts: [] })).toBe(false);
      expect(isAllowedUrl("https://example.com/", [])).toBe(false);
    });

    test("omitted allowHosts preserves existing behavior exactly", () => {
      const guard = new SSRFGuard();
      expect(guard.validateUrl("https://example.com/")).toBeInstanceOf(URL);
      expect(guard.validateUrl("http://example.com/")).toBeInstanceOf(URL);
      expect(() => guard.validateUrl("http://127.0.0.1/")).toThrow();
      expect(isAllowedUrl("https://example.com/")).toBe(true);
      expect(isAllowedUrl("http://127.0.0.1/")).toBe(false);
    });

    test("handles URL object and string interchangeably in isAllowedUrl", () => {
      expect(isAllowedUrl(new URL("https://api.example.com/"), { allowHosts: ["api.example.com"] })).toBe(true);
      expect(isAllowedUrl("https://api.example.com/", { allowHosts: ["api.example.com"] })).toBe(true);
    });

    test("public helpers normalizeHostname and matchHostAllowlist work directly", () => {
      expect(normalizeHostname("  I.IMGUR.COM.  ")).toBe("i.imgur.com");
      expect(normalizeHostname("[::1]")).toBe("::1");
      expect(matchHostAllowlist("i.imgur.com", ["*.imgur.com"])).toBe(true);
      expect(matchHostAllowlist("imgur.com", ["*.imgur.com"])).toBe(false);
      expect(matchHostAllowlist("example.com", [])).toBe(false);
    });
  });

  describe("issue #93: wildcard boundaries and deceptive URLs", () => {
    const allowHosts = ["*.imgur.com"];
    const guard = new SSRFGuard({ allowHosts });

    test("*.imgur.com matches exactly one subdomain level", () => {
      expect(guard.validateUrl("https://i.imgur.com/pic.png")).toBeInstanceOf(URL);
      expect(guard.validateUrl("https://api.imgur.com/data")).toBeInstanceOf(URL);
      expect(guard.validateUrl("https://foo-bar.imgur.com/")).toBeInstanceOf(URL);

      expect(isAllowedUrl("https://i.imgur.com/pic.png", { allowHosts })).toBe(true);
      expect(isAllowedUrl("https://api.imgur.com/data", { allowHosts })).toBe(true);
    });

    test("*.imgur.com NEVER matches apex domain", () => {
      expect(() => guard.validateUrl("https://imgur.com/")).toThrow();
      expect(isAllowedUrl("https://imgur.com/", { allowHosts })).toBe(false);
    });

    test("*.imgur.com NEVER matches nested subdomains", () => {
      expect(() => guard.validateUrl("https://sub.i.imgur.com/")).toThrow();
      expect(() => guard.validateUrl("https://a.b.c.imgur.com/")).toThrow();
      expect(isAllowedUrl("https://sub.i.imgur.com/", { allowHosts })).toBe(false);
      expect(isAllowedUrl("https://a.b.c.imgur.com/", { allowHosts })).toBe(false);
    });

    test("*.imgur.com NEVER matches lookalikes or deceptive domains", () => {
      expect(() => guard.validateUrl("https://evilimgur.com/")).toThrow();
      expect(() => guard.validateUrl("https://imgur.com.evil.example/")).toThrow();
      expect(() => guard.validateUrl("https://i.imgur.com@evil.example/")).toThrow();
      expect(() => guard.validateUrl("https://i.imgur.com:secret@evil.example/")).toThrow();

      expect(isAllowedUrl("https://evilimgur.com/", { allowHosts })).toBe(false);
      expect(isAllowedUrl("https://imgur.com.evil.example/", { allowHosts })).toBe(false);
      expect(isAllowedUrl("https://i.imgur.com@evil.example/", { allowHosts })).toBe(false);
      expect(isAllowedUrl("https://i.imgur.com:secret@evil.example/", { allowHosts })).toBe(false);
    });

    test("allows both apex and subdomain when both explicitly configured", () => {
      const dualGuard = new SSRFGuard({ allowHosts: ["imgur.com", "*.imgur.com"] });
      expect(dualGuard.validateUrl("https://imgur.com/")).toBeInstanceOf(URL);
      expect(dualGuard.validateUrl("https://i.imgur.com/")).toBeInstanceOf(URL);
      expect(() => dualGuard.validateUrl("https://sub.i.imgur.com/")).toThrow();
      expect(() => dualGuard.validateUrl("https://evilimgur.com/")).toThrow();
    });

    test("rejects malformed URLs in isAllowedUrl without throwing", () => {
      for (const bad of [
        "not-a-url",
        "",
        null,
        undefined,
        12345,
        {},
        "javascript:alert(1)",
        "data:text/html,test",
        "file:///etc/passwd",
        "https://",
        "http:///"
      ]) {
        expect(isAllowedUrl(bad, { allowHosts: ["example.com"] })).toBe(false);
      }
    });
  });

  describe("issue #93: hostname normalization (case, trailing dots, IDN/IDNA)", () => {
    test("normalizes hostname case", () => {
      const guard = new SSRFGuard({ allowHosts: ["*.imgur.com", "example.com"] });
      expect(guard.validateUrl("https://I.IMGUR.COM/pic")).toBeInstanceOf(URL);
      expect(guard.validateUrl("https://EXAMPLE.COM/page")).toBeInstanceOf(URL);
      expect(isAllowedUrl("https://I.IMGUR.COM/pic", { allowHosts: ["*.imgur.com"] })).toBe(true);

      const upperPatternGuard = new SSRFGuard({ allowHosts: ["*.IMGUR.COM", "EXAMPLE.COM"] });
      expect(upperPatternGuard.validateUrl("https://i.imgur.com/pic")).toBeInstanceOf(URL);
      expect(upperPatternGuard.validateUrl("https://example.com/page")).toBeInstanceOf(URL);
      expect(isAllowedUrl("https://i.imgur.com/pic", { allowHosts: ["*.IMGUR.COM"] })).toBe(true);
    });

    test("normalizes trailing dots safely in host and pattern", () => {
      const guard = new SSRFGuard({ allowHosts: ["*.imgur.com.", "example.com."] });
      expect(guard.validateUrl("https://i.imgur.com./pic")).toBeInstanceOf(URL);
      expect(guard.validateUrl("https://i.imgur.com/pic")).toBeInstanceOf(URL);
      expect(guard.validateUrl("https://example.com./")).toBeInstanceOf(URL);
      expect(guard.validateUrl("https://example.com/")).toBeInstanceOf(URL);

      expect(isAllowedUrl("https://i.imgur.com./pic", { allowHosts: ["*.imgur.com"] })).toBe(true);
      expect(isAllowedUrl("https://i.imgur.com/pic", { allowHosts: ["*.imgur.com."] })).toBe(true);
    });

    test("normalizes IDN/IDNA Unicode and Punycode representations", () => {
      const idnGuard = new SSRFGuard({ allowHosts: ["*.münchen.de", "zürich.ch"] });
      expect(idnGuard.validateUrl("https://stadt.münchen.de/")).toBeInstanceOf(URL);
      expect(idnGuard.validateUrl("https://stadt.xn--mnchen-3ya.de/")).toBeInstanceOf(URL);
      expect(idnGuard.validateUrl("https://STADT.MÜNCHEN.DE./")).toBeInstanceOf(URL);
      expect(idnGuard.validateUrl("https://zürich.ch/")).toBeInstanceOf(URL);
      expect(idnGuard.validateUrl("https://xn--zrich-kva.ch/")).toBeInstanceOf(URL);

      // Apex and nested subdomains must not match wildcard
      expect(() => idnGuard.validateUrl("https://münchen.de/")).toThrow();
      expect(() => idnGuard.validateUrl("https://sub.stadt.münchen.de/")).toThrow();

      // Reverse pattern configuration (Punycode pattern matches Unicode URL)
      const punycodeGuard = new SSRFGuard({ allowHosts: ["*.xn--mnchen-3ya.de"] });
      expect(punycodeGuard.validateUrl("https://stadt.münchen.de/")).toBeInstanceOf(URL);
      expect(punycodeGuard.validateUrl("https://stadt.xn--mnchen-3ya.de/")).toBeInstanceOf(URL);

      expect(isAllowedUrl("https://stadt.münchen.de/", { allowHosts: ["*.münchen.de"] })).toBe(true);
      expect(isAllowedUrl("https://stadt.xn--mnchen-3ya.de/", { allowHosts: ["*.münchen.de"] })).toBe(true);
      expect(isAllowedUrl("https://münchen.de/", { allowHosts: ["*.münchen.de"] })).toBe(false);
      expect(isAllowedUrl("https://sub.stadt.münchen.de/", { allowHosts: ["*.münchen.de"] })).toBe(false);
    });
  });

  describe("issue #93: schemes and default HTTPS enforcement", () => {
    test("enforces HTTPS by default when allowHosts is configured", () => {
      const guard = new SSRFGuard({ allowHosts: ["*.imgur.com"] });
      expect(guard.validateUrl("https://i.imgur.com/test")).toBeInstanceOf(URL);
      expect(() => guard.validateUrl("http://i.imgur.com/test")).toThrow();
      expect(() => guard.validateUrl("ftp://i.imgur.com/test")).toThrow();

      expect(isAllowedUrl("https://i.imgur.com/test", { allowHosts: ["*.imgur.com"] })).toBe(true);
      expect(isAllowedUrl("http://i.imgur.com/test", { allowHosts: ["*.imgur.com"] })).toBe(false);
      expect(isAllowedUrl("ftp://i.imgur.com/test", { allowHosts: ["*.imgur.com"] })).toBe(false);
    });

    test("permits other schemes only via explicit opt-in", () => {
      const guard = new SSRFGuard({ allowHosts: ["*.imgur.com"], allowProtocols: ["http:", "https:"] });
      expect(guard.validateUrl("http://i.imgur.com/test")).toBeInstanceOf(URL);
      expect(guard.validateUrl("https://i.imgur.com/test")).toBeInstanceOf(URL);

      expect(isAllowedUrl("http://i.imgur.com/test", { allowHosts: ["*.imgur.com"], allowProtocols: ["http:", "https:"] })).toBe(true);
      expect(isAllowedUrl("http://i.imgur.com/test", { allowHosts: ["*.imgur.com"], allowProtocols: ["http", "https"] })).toBe(true);
      expect(isAllowedUrl("http://i.imgur.com/test", { allowHosts: ["*.imgur.com"], allowSchemes: ["http", "https"] })).toBe(true);
    });
  });

  describe("issue #93: internal-IP protections retained with allowHosts", () => {
    test("rejects private/loopback/metadata addresses even if added to allowHosts", () => {
      for (const ip of ["127.0.0.1", "localhost", "169.254.169.254", "10.0.0.1", "[::1]", "::ffff:127.0.0.1"]) {
        const guard = new SSRFGuard({ allowHosts: [ip] });
        expect(() => guard.validateUrl(`https://${ip}/`)).toThrow();
        expect(isAllowedUrl(`https://${ip}/`, { allowHosts: [ip] })).toBe(false);
      }
    });

    test("assertResolvedSafe rejects allowed hostnames that resolve to private addresses", async () => {
      const guard = new SSRFGuard({
        allowHosts: ["hooks.example.com"],
        resolveHost: async () => ["127.0.0.1"]
      });
      await expect(guard.assertResolvedSafe("https://hooks.example.com/hook")).rejects.toMatchObject({
        code: "SSRF_BLOCKED"
      });
    });

    test("assertResolvedSafe allows allowed hostnames resolving to public addresses", async () => {
      const guard = new SSRFGuard({
        allowHosts: ["hooks.example.com"],
        resolveHost: async () => ["93.184.216.34"]
      });
      await expect(guard.assertResolvedSafe("https://hooks.example.com/hook")).resolves.toBeInstanceOf(URL);
    });
  });

  describe("issue #93: DNS pinning in lookup", () => {
    const lookupAsync = (lookup, host, options = {}) =>
      new Promise((resolve, reject) => {
        lookup(host, options, (err, address, family) => (err ? reject(err) : resolve({ address, family })));
      });

    test("pins connection to validated public IP without calling resolver", async () => {
      let resolverCalled = false;
      const guard = new SSRFGuard({
        allowHosts: ["example.com"],
        resolveHost: async () => {
          resolverCalled = true;
          return ["1.2.3.4"];
        }
      });

      const pinnedLookup = guard.createSafeLookup({ "example.com": "93.184.216.34" });
      const result = await lookupAsync(pinnedLookup, "example.com", {});
      expect(result).toEqual({ address: "93.184.216.34", family: 4 });
      expect(resolverCalled).toBe(false);
    });

    test("createPinnedLookup helper pins address for specific host", async () => {
      const guard = new SSRFGuard({ allowHosts: ["api.example.com"] });
      const pinnedLookup = guard.createPinnedLookup("api.example.com", "93.184.216.34");
      const result = await lookupAsync(pinnedLookup, "api.example.com", {});
      expect(result).toEqual({ address: "93.184.216.34", family: 4 });
    });

    test("rejects pinned address if it is private or loopback", async () => {
      const guard = new SSRFGuard({ allowHosts: ["example.com"] });
      const pinnedLookup = guard.createSafeLookup({ "example.com": "10.0.0.1" });
      await expect(lookupAsync(pinnedLookup, "example.com", {})).rejects.toMatchObject({
        code: "SSRF_BLOCKED"
      });
    });

    test("rejects lookup if host is not in allowHosts", async () => {
      const guard = new SSRFGuard({ allowHosts: ["example.com"] });
      const pinnedLookup = guard.createSafeLookup({ "evil.example": "93.184.216.34" });
      await expect(lookupAsync(pinnedLookup, "evil.example", {})).rejects.toMatchObject({
        code: "SSRF_BLOCKED"
      });
    });
  });

  describe("issue #93: redirect allowlist bypass prevention & redirect limits", () => {
    test("validateRedirectChain rejects hops outside allowlist", () => {
      const guard = new SSRFGuard({ allowHosts: ["*.example.com"], maxRedirectHops: 3 });
      expect(() =>
        guard.validateRedirectChain(["https://a.example.com/1", "https://b.example.com/2", "https://evil.org/3"])
      ).toThrow();
      expect(
        guard.validateRedirectChain(["https://a.example.com/1", "https://b.example.com/2"])
      ).toBe(true);
    });

    test("SafeFetcher prevents redirect allowlist bypass", async () => {
      const guard = new SSRFGuard({
        allowHosts: ["api.example.com"],
        resolveHost: async () => ["93.184.216.34"]
      });
      const fetchImpl = jest.fn(async () => ({
        status: 302,
        headers: { get: (key) => (key === "location" ? "https://evil.attacker.com/steal" : null) },
        ok: false
      }));
      const safeFetcher = new SafeFetcher({ guard, fetchImpl });

      await expect(safeFetcher.fetch("https://api.example.com/start")).rejects.toMatchObject({
        code: "SSRF_BLOCKED"
      });
      expect(fetchImpl).toHaveBeenCalledTimes(1);
    });

    test("SafeFetcher follows redirect when destination is in allowlist", async () => {
      const guard = new SSRFGuard({
        allowHosts: ["api.example.com", "auth.example.com"],
        resolveHost: async () => ["93.184.216.34"]
      });
      let step = 0;
      const fetchImpl = jest.fn(async () => {
        step++;
        if (step === 1) {
          return {
            status: 302,
            headers: { get: (key) => (key === "location" ? "https://auth.example.com/login" : null) },
            ok: false
          };
        }
        return { status: 200, ok: true, headers: { get: () => null } };
      });
      const safeFetcher = new SafeFetcher({ guard, fetchImpl });
      const res = await safeFetcher.fetch("https://api.example.com/start");
      expect(res.status).toBe(200);
      expect(fetchImpl).toHaveBeenCalledTimes(2);
    });

    test("SafeFetcher blocks redirect to non-HTTPS scheme when HTTPS is enforced", async () => {
      const guard = new SSRFGuard({
        allowHosts: ["api.example.com"],
        resolveHost: async () => ["93.184.216.34"]
      });
      const fetchImpl = jest.fn(async () => ({
        status: 302,
        headers: { get: (key) => (key === "location" ? "http://api.example.com/unencrypted" : null) },
        ok: false
      }));
      const safeFetcher = new SafeFetcher({ guard, fetchImpl });
      await expect(safeFetcher.fetch("https://api.example.com/start")).rejects.toMatchObject({
        code: "SSRF_BLOCKED"
      });
    });

    test("SafeFetcher enforces redirect hop limit with allowlist", async () => {
      const guard = new SSRFGuard({
        allowHosts: ["api.example.com"],
        maxRedirectHops: 2,
        resolveHost: async () => ["93.184.216.34"]
      });
      const fetchImpl = jest.fn(async () => ({
        status: 302,
        headers: { get: (key) => (key === "location" ? "https://api.example.com/loop" : null) },
        ok: false
      }));
      const safeFetcher = new SafeFetcher({ guard, fetchImpl });
      await expect(safeFetcher.fetch("https://api.example.com/loop")).rejects.toMatchObject({
        code: "SSRF_BLOCKED"
      });
      expect(fetchImpl).toHaveBeenCalledTimes(3); // hop 0, 1, 2
    });
  });
});
