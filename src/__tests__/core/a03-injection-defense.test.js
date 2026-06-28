import { describe, expect, test } from "@jest/globals";
import { InputSanitizer, InputValidator } from "../../core/a03-injection-defense/index.js";

describe("A03 injection defense", () => {
  test("sanitizes malicious payload", () => {
    const sanitizer = new InputSanitizer("strict");
    const result = sanitizer.sanitizeHTML('<img src=x onerror=alert(1)><script>alert(1)</script>safe');
    expect(result.includes("script")).toBe(false);
    expect(result.includes("onerror")).toBe(false);
  });

  test("returns structured validation failures", () => {
    const validator = new InputValidator();
    const output = validator.validateSchema(
      { email: "bad", password: "x" },
      {
        email: { required: true, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
        password: { required: true, minLength: 8 }
      }
    );
    expect(output.valid).toBe(false);
    expect(output.errors[0]).toHaveProperty("field");
    expect(output.errors[0]).toHaveProperty("code");
    expect(output.errors[0]).toHaveProperty("message");
  });
});