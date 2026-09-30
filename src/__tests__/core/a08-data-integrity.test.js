import { describe, expect, test } from "@jest/globals";
import { CSRFTokenManager, HTTPClient } from "../../core/a08-data-integrity/index.js";
import { SSRFGuard } from "../../core/a10-ssrf-defense/index.js";

describe("A08 data integrity", () => {
  test("rotates and validates csrf token", () => {
    const csrf = new CSRFTokenManager();
    const token = csrf.rotateToken();
    expect(csrf.attach({})["X-CSRF-Token"]).toBe(token);
    expect(csrf.validate(token)).toBe(true);
  });

  test("validate throws on a non-matching token", () => {
    const csrf = new CSRFTokenManager();
    csrf.rotateToken();
    expect(() => csrf.validate("not-the-real-token")).toThrow();
  });

  test("validate throws on a token of a different length (no timingSafeEqual crash)", () => {
    const csrf = new CSRFTokenManager();
    const token = csrf.rotateToken();
    expect(() => csrf.validate(token.slice(0, -1))).toThrow();
    expect(() => csrf.validate(`${token}x`)).toThrow();
  });

  test("injects auth and csrf headers in request", async () => {
    const csrf = new CSRFTokenManager();
    csrf.rotateToken();
    const fetchImpl = async (_url, options) => ({
      ok: true,
      status: 200,
      headers: new Headers(),
      clone: () => ({ json: async () => ({ headers: options.headers }) }),
      text: async () => ""
    });
    const client = new HTTPClient({
      csrfManager: csrf,
      tokenProvider: () => "access-token",
      fetchImpl
    });
    const res = await client.request("/x", { method: "GET" });
    expect(res.data.headers.Authorization).toContain("Bearer");
    expect(res.data.headers["X-CSRF-Token"]).toBeTruthy();
  });

  test("supports async token providers and request interceptors", async () => {
    const calls = [];
    const fetchImpl = async (_url, options) => {
      calls.push(options.headers.Authorization);
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        clone: () => ({ json: async () => ({ headers: options.headers }) }),
        text: async () => ""
      };
    };

    const client = new HTTPClient({
      tokenProvider: async () => "async-token",
      fetchImpl
    });

    client.addRequestInterceptor(async (config) => ({
      ...config,
      headers: { ...config.headers, "X-Trace-Id": "trace-1" }
    }));

    const res = await client.request("/x", { method: "GET" });
    expect(calls).toEqual(["Bearer async-token"]);
    expect(res.data.headers["X-Trace-Id"]).toBe("trace-1");
  });

  test("wraps non-ok responses with status metadata", async () => {
    const client = new HTTPClient({
      fetchImpl: async () => ({
        ok: false,
        status: 403,
        headers: new Headers(),
        clone: () => ({ json: async () => ({ reason: "denied" }) }),
        text: async () => "denied"
      })
    });

    const res = await client.request("/x", { method: "GET" });
    expect(res.error).toMatchObject({
      code: "INVALID_INPUT",
      details: { status: 403, body: { reason: "denied" } }
    });
  });

  test("blocks outbound request when SSRF policy rejects target", async () => {
    const fetchImpl = async () => {
      throw new Error("fetch should not be called");
    };
    const client = new HTTPClient({
      outboundRequestPolicy: new SSRFGuard(),
      fetchImpl
    });

    await expect(client.request("http://127.0.0.1/internal", { method: "GET" })).rejects.toThrow();
  });

  test("refuses to attach Authorization/CSRF credentials to an absolute cross-origin URL", async () => {
    const csrf = new CSRFTokenManager();
    csrf.rotateToken();
    const fetchImpl = async () => {
      throw new Error("fetch should not be called");
    };
    const client = new HTTPClient({
      baseUrl: "",
      csrfManager: csrf,
      tokenProvider: () => "SECRET-BEARER-TOKEN",
      fetchImpl
    });

    await expect(client.request("https://evil.example.com/collect")).rejects.toThrow();
  });

  test("allows credentialed requests to baseUrl's own origin", async () => {
    const csrf = new CSRFTokenManager();
    csrf.rotateToken();
    let captured = null;
    const fetchImpl = async (url, cfg) => {
      captured = { url, headers: cfg.headers };
      return { ok: true, status: 200, headers: new Headers(), clone: () => ({ json: async () => ({}) }), text: async () => "" };
    };
    const client = new HTTPClient({
      baseUrl: "https://api.example.com",
      csrfManager: csrf,
      tokenProvider: () => "token",
      fetchImpl
    });

    await client.request("/users");
    expect(captured.headers.Authorization).toContain("Bearer");

    await expect(client.request("https://attacker.example.com/steal")).rejects.toThrow();
  });

  test("allows credentialed requests to an explicitly allowlisted origin", async () => {
    const fetchImpl = async () => ({
      ok: true,
      status: 200,
      headers: new Headers(),
      clone: () => ({ json: async () => ({}) }),
      text: async () => ""
    });
    const client = new HTTPClient({
      tokenProvider: () => "token",
      allowedOrigins: ["https://trusted-partner.example.com"],
      fetchImpl
    });

    await expect(client.request("https://trusted-partner.example.com/api")).resolves.toMatchObject({ ok: true });
  });

  test("does not send response-only security headers on requests", async () => {
    let sent = null;
    const client = new HTTPClient({
      fetchImpl: async (_url, cfg) => {
        sent = cfg.headers;
        return { ok: true, status: 200, headers: new Headers(), clone: () => ({ json: async () => ({}) }), text: async () => "" };
      }
    });
    await client.request("/x");
    expect(sent["X-Frame-Options"]).toBeUndefined();
    expect(sent["X-Content-Type-Options"]).toBeUndefined();
  });

  const redirectResponse = (location, status = 302) => ({
    ok: false,
    status,
    headers: { get: (key) => (key === "location" ? location : null) }
  });
  const okResponse = () => ({
    ok: true,
    status: 200,
    headers: new Headers(),
    clone: () => ({ json: async () => ({}) }),
    text: async () => ""
  });

  test("re-validates redirect targets against the SSRF policy instead of auto-following", async () => {
    const calls = [];
    const client = new HTTPClient({
      outboundRequestPolicy: new SSRFGuard({ resolveHost: async () => ["93.184.216.34"] }),
      fetchImpl: async (url, cfg) => {
        calls.push({ url, redirect: cfg.redirect });
        return redirectResponse("http://169.254.169.254/latest/meta-data/");
      }
    });
    await expect(client.request("https://api.example.com/start")).rejects.toMatchObject({ code: "SSRF_BLOCKED" });
    expect(calls).toEqual([{ url: "https://api.example.com/start", redirect: "manual" }]);
  });

  test("uses DNS-resolved validation when the policy supports it", async () => {
    const client = new HTTPClient({
      outboundRequestPolicy: new SSRFGuard({ resolveHost: async () => ["10.0.0.8"] }),
      fetchImpl: async () => {
        throw new Error("fetch should not be called");
      }
    });
    await expect(client.request("https://internal-alias.example.com/")).rejects.toMatchObject({ code: "SSRF_BLOCKED" });
  });

  test("strips credentials when a redirect leaves the original origin and downgrades POST on 303", async () => {
    const csrf = new CSRFTokenManager();
    csrf.rotateToken();
    const calls = [];
    const responses = [redirectResponse("https://cdn.example.net/file", 303), okResponse()];
    const client = new HTTPClient({
      baseUrl: "https://api.example.com",
      csrfManager: csrf,
      tokenProvider: () => "SECRET",
      outboundRequestPolicy: new SSRFGuard({ resolveHost: async () => ["93.184.216.34"] }),
      fetchImpl: async (url, cfg) => {
        calls.push({ url, cfg });
        return responses.shift();
      }
    });
    const res = await client.request("/upload", { method: "POST", body: "data" });
    expect(res.ok).toBe(true);
    expect(calls[0].cfg.headers.Authorization).toBe("Bearer SECRET");
    expect(calls[1].url).toBe("https://cdn.example.net/file");
    expect(calls[1].cfg.headers.Authorization).toBeUndefined();
    expect(calls[1].cfg.headers["X-CSRF-Token"]).toBeUndefined();
    expect(calls[1].cfg.method).toBe("GET");
    expect(calls[1].cfg.body).toBeUndefined();
  });

  test("enforces the policy's redirect hop limit", async () => {
    const client = new HTTPClient({
      outboundRequestPolicy: new SSRFGuard({ maxRedirectHops: 1, resolveHost: async () => ["93.184.216.34"] }),
      fetchImpl: async () => redirectResponse("https://api.example.com/loop")
    });
    await expect(client.request("https://api.example.com/loop")).rejects.toThrow("Redirect hop limit exceeded");
  });

  test("credential origin check resolves URLs the way fetch does (empty baseUrl)", async () => {
    const client = new HTTPClient({
      tokenProvider: () => "VICTIM-TOKEN",
      fetchImpl: async () => {
        throw new Error("fetch should not be called");
      }
    });
    for (const url of [" https://evil.example/x", "\thttps://evil.example/x", "//evil.example/x", "/\\evil.example/x", "\\\\evil.example/x"]) {
      await expect(client.request(url)).rejects.toMatchObject({ code: "CREDENTIAL_LEAK_BLOCKED" });
    }
  });

  test("empty baseUrl allows the page's own origin, relative or absolute", async () => {
    const urls = [];
    const client = new HTTPClient({
      tokenProvider: () => "token",
      fetchImpl: async (url) => {
        urls.push(url);
        return okResponse();
      }
    });
    await client.request("/api/items");
    await client.request(`${window.location.origin}/api/items`);
    expect(urls).toEqual(["/api/items", `${window.location.origin}/api/items`]);
  });

  test("never sends credentials to opaque-origin URLs", async () => {
    const client = new HTTPClient({ tokenProvider: () => "token", fetchImpl: async () => okResponse() });
    await expect(client.request("data:text/plain,hi")).rejects.toMatchObject({ code: "CREDENTIAL_LEAK_BLOCKED" });
  });

  test("CSRF validate rejects non-ASCII lookalikes of the real token", () => {
    const csrf = new CSRFTokenManager();
    const token = csrf.rotateToken();
    const lookalike = [...token].map((c) => String.fromCharCode(c.charCodeAt(0) + 0x100)).join("");
    expect(() => csrf.validate(lookalike)).toThrow("CSRF token validation failed");
    expect(csrf.validate(token)).toBe(true);
  });

  test("CSRF validate still accepts server-issued standard base64 tokens from custom storage", () => {
    const csrf = new CSRFTokenManager({ storage: { get: () => "ab+/cd==", set: () => {} } });
    expect(csrf.validate("ab+/cd==")).toBe(true);
  });

  test("a browser opaque redirect fails with a clear SSRF error instead of a blank response", async () => {
    const client = new HTTPClient({
      outboundRequestPolicy: new SSRFGuard({ resolveHost: async () => ["93.184.216.34"] }),
      fetchImpl: async () => ({ type: "opaqueredirect", status: 0, ok: false, headers: new Headers() })
    });
    await expect(client.request("https://api.example.com/moved")).rejects.toMatchObject({
      code: "SSRF_BLOCKED",
      message: expect.stringContaining("opaque redirect")
    });
  });

  describe("credentialed requests without an SSRF policy", () => {
    const credentialedClient = (fetchImpl, extra = {}) => {
      const csrf = new CSRFTokenManager();
      csrf.rotateToken();
      return new HTTPClient({ baseUrl: "https://api.example.com", csrfManager: csrf, tokenProvider: () => "SECRET", fetchImpl, ...extra });
    };

    test("strip credentials when a redirect leaves the origin", async () => {
      const calls = [];
      const responses = [redirectResponse("https://third-party.example/collect"), okResponse()];
      const client = credentialedClient(async (url, cfg) => (calls.push({ url, cfg }), responses.shift()));
      await client.request("/start");
      expect(calls[0].cfg.redirect).toBe("manual");
      expect(calls[1].url).toBe("https://third-party.example/collect");
      expect(calls[1].cfg.headers.Authorization).toBeUndefined();
      expect(calls[1].cfg.headers["X-CSRF-Token"]).toBeUndefined();
    });

    test("keep credentials on a same-origin redirect", async () => {
      const calls = [];
      const responses = [redirectResponse("/v2/start", 307), okResponse()];
      const client = credentialedClient(async (url, cfg) => (calls.push({ url, cfg }), responses.shift()));
      await client.request("/start");
      expect(calls[1].url).toBe("https://api.example.com/v2/start");
      expect(calls[1].cfg.headers.Authorization).toBe("Bearer SECRET");
      expect(calls[1].cfg.headers["X-CSRF-Token"]).toBeTruthy();
    });

    test("refuse an opaque browser redirect instead of forwarding credentials blindly", async () => {
      const client = credentialedClient(async () => ({ type: "opaqueredirect", status: 0, ok: false, headers: new Headers() }));
      await expect(client.request("/start")).rejects.toMatchObject({ code: "CREDENTIAL_LEAK_BLOCKED" });
    });

    test("an explicit redirect mode is respected", async () => {
      const calls = [];
      const client = credentialedClient(async (url, cfg) => (calls.push(cfg), okResponse()));
      await client.request("/start", { redirect: "follow" });
      expect(calls).toHaveLength(1);
      expect(calls[0].redirect).toBe("follow");
    });

    test("requests without credentials keep fetch's default redirect handling", async () => {
      const calls = [];
      const client = new HTTPClient({ fetchImpl: async (url, cfg) => (calls.push(cfg), okResponse()) });
      await client.request("https://public.example/data");
      expect(calls[0].redirect).toBeUndefined();
    });
  });
});
