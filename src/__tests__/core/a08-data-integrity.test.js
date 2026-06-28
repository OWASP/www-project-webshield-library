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
});