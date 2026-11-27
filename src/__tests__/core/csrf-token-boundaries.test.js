import { afterEach, describe, expect, test } from "@jest/globals";
import { CSRFTokenManager } from "../../core/a08-data-integrity/index.js";

const clearCookies = () => {
  for (const cookie of document.cookie.split(";")) {
    const name = cookie.split("=")[0].trim();
    if (name) document.cookie = `${name}=; Max-Age=0; Path=/`;
  }
};

afterEach(clearCookies);

describe("CSRF token lifecycle boundaries", () => {
  test("replacing a server token invalidates the previous token", () => {
    const manager = new CSRFTokenManager();
    manager.setToken("old-server-token");
    manager.setToken("new-server-token");
    expect(() => manager.validate("old-server-token")).toThrow(expect.objectContaining({ code: "CSRF_INVALID", details: {} }));
    expect(manager.validate("new-server-token")).toBe(true);
  });

  test.each([undefined, null, 123, "", "has space", "has\ttab", "has\nnewline", "\u007f", "\u0100"])(
    "rejects invalid server token %p without overwriting the current token",
    (token) => {
      const manager = new CSRFTokenManager();
      manager.setToken("valid-token");
      expect(() => manager.setToken(token)).toThrow(expect.objectContaining({ code: "INVALID_INPUT", details: {} }));
      expect(manager.getToken()).toBe("valid-token");
      expect(manager.validate("valid-token")).toBe(true);
    }
  );

  test("a missing stored token cannot validate or add a header", () => {
    const manager = new CSRFTokenManager();
    const headers = { Accept: "application/json" };
    expect(manager.attach(headers)).toEqual(headers);
    expect(() => manager.validate("candidate")).toThrow(expect.objectContaining({ code: "CSRF_INVALID" }));
  });
});

describe("cookie-backed CSRF token boundaries", () => {
  test("matches the complete custom cookie name, not a prefix or suffix", () => {
    document.cookie = "prefix-APP-CSRF=wrong-prefix";
    document.cookie = "APP-CSRF-suffix=wrong-suffix";
    const manager = CSRFTokenManager.fromCookie("APP-CSRF");
    expect(manager.getToken()).toBeNull();
    document.cookie = "APP-CSRF=correct%2Btoken%3D%3D";
    expect(manager.getToken()).toBe("correct+token==");
    expect(manager.validate("correct+token==")).toBe(true);
  });

  test.each(["%", "%GG", "%E0%A4%A", ""])("fails closed for malformed or empty cookie %p", (value) => {
    document.cookie = `XSRF-TOKEN=${value}`;
    const manager = CSRFTokenManager.fromCookie();
    expect(manager.getToken()).toBeNull();
    expect(manager.attach({ Accept: "application/json" })).toEqual({ Accept: "application/json" });
    expect(() => manager.validate("candidate")).toThrow(expect.objectContaining({ code: "CSRF_INVALID" }));
  });

  test("reads rotation and deletion through the same manager instance", () => {
    const manager = CSRFTokenManager.fromCookie();
    document.cookie = "XSRF-TOKEN=first";
    expect(manager.validate("first")).toBe(true);
    document.cookie = "XSRF-TOKEN=second";
    expect(manager.attach({})["X-CSRF-Token"]).toBe("second");
    expect(() => manager.validate("first")).toThrow(expect.objectContaining({ code: "CSRF_INVALID" }));
    expect(manager.validate("second")).toBe(true);
    document.cookie = "XSRF-TOKEN=; Max-Age=0; Path=/";
    expect(manager.attach({})).toEqual({});
    expect(() => manager.validate("second")).toThrow(expect.objectContaining({ code: "CSRF_INVALID" }));
  });

  test("refuses client-side replacement without changing the server cookie", () => {
    document.cookie = "XSRF-TOKEN=server-token";
    const manager = CSRFTokenManager.fromCookie();
    expect(() => manager.setToken("replacement")).toThrow(expect.objectContaining({ code: "MISCONFIGURATION", details: {} }));
    expect(manager.getToken()).toBe("server-token");
    expect(manager.validate("server-token")).toBe(true);
  });
});
