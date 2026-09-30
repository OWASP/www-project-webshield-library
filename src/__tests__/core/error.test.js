import { describe, expect, test } from "@jest/globals";
import { SecurityError, SecurityErrorCode } from "../../core/error/index.js";

describe("SecurityError", () => {
  test("captures normalized error codes and metadata", () => {
    const error = new SecurityError(SecurityErrorCode.ACCESS_DENIED, "Denied", {
      resource: "reports",
      action: "read"
    });

    expect(error).toMatchObject({
      name: "SecurityError",
      code: SecurityErrorCode.ACCESS_DENIED,
      message: "Denied",
      details: {
        resource: "reports",
        action: "read"
      }
    });
  });

  test("instanceof works across copies of the package via the registry brand", () => {
    // What another copy of the module (second installed version, modules/* import) produces.
    const fromOtherCopy = new Error("blocked");
    Object.defineProperty(fromOtherCopy, Symbol.for("@owasp-webshield/core.SecurityError"), { value: true });
    expect(fromOtherCopy instanceof SecurityError).toBe(true);

    expect(new Error("plain") instanceof SecurityError).toBe(false);
    expect({ code: "ACCESS_DENIED" } instanceof SecurityError).toBe(false);
    expect(null instanceof SecurityError).toBe(false);
    expect(new SecurityError(SecurityErrorCode.ACCESS_DENIED, "x") instanceof Error).toBe(true);
  });

  test("subclasses keep normal prototype-based instanceof", () => {
    class RateLimitError extends SecurityError {}
    const base = new SecurityError(SecurityErrorCode.ACCESS_DENIED, "x");
    const sub = new RateLimitError(SecurityErrorCode.ACCESS_DENIED, "y");
    expect(sub instanceof RateLimitError).toBe(true);
    expect(sub instanceof SecurityError).toBe(true);
    expect(base instanceof RateLimitError).toBe(false);
  });

  test("the brand is not enumerable, so errors serialize as before", () => {
    const error = new SecurityError(SecurityErrorCode.ACCESS_DENIED, "Denied", { resource: "r" });
    expect(Object.keys(error)).toEqual(["name", "code", "details"]);
  });
});
