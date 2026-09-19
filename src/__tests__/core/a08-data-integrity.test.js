import { describe, expect, test } from "@jest/globals";
import { CSRFTokenManager, HTTPClient } from "../../core/a08-data-integrity/index.js";
import { SSRFGuard } from "../../core/a10-ssrf-defense/index.js";

describe("A08 data integrity", () => {
  test("rotates and validates csrf token", () => {
    const csrf = new CSRFTokenManager();
    const token = csrf.rotateToken();
    expect(csrf.attach({})["X-CSRF-Token"]).toBe(token);
    expect(csrf.validate(token)).toBe(true);
    expect(() => csrf.validate(`${token}x`)).toThrow();
    expect(() => csrf.validate(`${"x".repeat(token.length - 1)}y`)).toThrow();
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
});
