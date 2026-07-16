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
});