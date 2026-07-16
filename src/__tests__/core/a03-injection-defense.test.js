import { describe, expect, test } from "@jest/globals";
import { InputSanitizer, InputValidator } from "../../core/a03-injection-defense/index.js";

describe("A03 injection defense", () => {
  test("sanitizes malicious payload", () => {
    const sanitizer = new InputSanitizer("strict");
    const result = sanitizer.sanitizeHTML('<img src=x onerror=alert(1)><script>alert(1)</script>safe');
    expect(result.includes("script")).toBe(false);
    expect(result.includes("onerror")).toBe(false);
  });

  test("moderate profile keeps markup while stripping active content", () => {
    const sanitizer = new InputSanitizer("moderate");
    const result = sanitizer.sanitizeHTML('<a href="javascript:alert(1)" onclick="alert(1)">safe</a>');

    expect(result).toContain("<a href=\"alert(1)\">safe</a>");
    expect(result.includes("onclick")).toBe(false);
    expect(result.includes("javascript:")).toBe(false);
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

  test("validates helper rules for email, url, and length", () => {
    const validator = new InputValidator();

    expect(validator.validateEmail("user@example.com")).toBe(true);
    expect(validator.validateEmail("bad-email")).toBe(false);
    expect(validator.validateUrl("https://example.com/api")).toBe(true);
    expect(validator.validateUrl("ftp://example.com")).toBe(false);
    expect(validator.validateLength("secret", { min: 6, max: 10 })).toBe(true);
    expect(validator.validateLength("x", { min: 2 })).toBe(false);
  });
});