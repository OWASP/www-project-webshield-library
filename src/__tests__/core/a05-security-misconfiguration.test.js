import { describe, expect, test } from "@jest/globals";
import { HardeningReporter, SecurityConfigManager } from "../../core/a05-security-misconfiguration/index.js";
import { SecurityErrorCode } from "../../core/error/index.js";

describe("A05 security misconfiguration", () => {
  test("reports hardening findings", () => {
    const manager = new SecurityConfigManager({ debug: true, cors: { origin: "*" }, cookies: { secure: false } });
    const report = new HardeningReporter(manager).generate();
    expect(report.length).toBeGreaterThan(0);
  });

  test("rejects invalid schema values", () => {
    const manager = new SecurityConfigManager({ debug: "yes" });
    expect(() => manager.validateSchema()).toThrow(
      expect.objectContaining({ code: SecurityErrorCode.MISCONFIGURATION })
    );
  });

  test("detects sameSite none as a medium severity finding", () => {
    const manager = new SecurityConfigManager({ cookies: { sameSite: "None" } });
    expect(manager.detectUnsafeSettings()).toContainEqual({ id: "samesite_none", severity: "medium" });
  });

  test("flags reflected and credentialed any-origin CORS", () => {
    const ids = (config) => new SecurityConfigManager(config).detectUnsafeSettings().map((f) => f.id);
    expect(ids({ cors: { origin: true } })).toEqual(["reflected_cors"]);
    expect(ids({ cors: { origin: true, credentials: true } })).toEqual(["reflected_cors", "credentialed_any_origin_cors"]);
    expect(ids({ cors: { origin: ["https://a.example", "*"] } })).toEqual(["wildcard_cors"]);
    expect(ids({ cors: { origin: "https://a.example", credentials: true } })).toEqual([]);
  });

  test("defaults cookies to httpOnly and flags turning it off", () => {
    expect(new SecurityConfigManager().config.cookies.httpOnly).toBe(true);
    expect(new SecurityConfigManager({ cookies: { httpOnly: false } }).detectUnsafeSettings()).toContainEqual({
      id: "cookie_not_httponly",
      severity: "medium"
    });
  });
});
