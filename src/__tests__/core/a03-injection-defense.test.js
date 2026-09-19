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

    expect(result).toContain("<a>safe</a>");
    expect(result.includes("onclick")).toBe(false);
    expect(result.includes("javascript:")).toBe(false);
  });

  test("moderate profile drops unclosed script tags and their content entirely", () => {
    const sanitizer = new InputSanitizer("moderate");
    const result = sanitizer.sanitizeHTML('<script src="//evil.example/x.js">');
    expect(result.includes("<script")).toBe(false);
    expect(result.includes("evil.example")).toBe(false);
  });

  test("moderate profile blocks attribute-separator event handlers (no whitespace before 'on*')", () => {
    const sanitizer = new InputSanitizer("moderate");
    const result = sanitizer.sanitizeHTML("<svg/onload=alert(document.domain)>");
    expect(/on\w+\s*=/i.test(result)).toBe(false);
    expect(result.includes("<svg")).toBe(false);
  });

  test("moderate profile blocks obfuscated javascript: protocol (case, whitespace, entities)", () => {
    const sanitizer = new InputSanitizer("moderate");
    const mixedCase = sanitizer.sanitizeHTML('<a href="jAvAsCrIpT:alert(1)">x</a>');
    const whitespace = sanitizer.sanitizeHTML('<a href="java\tscript:alert(1)">x</a>');
    const entityEncoded = sanitizer.sanitizeHTML('<a href="&#106;avascript:alert(1)">x</a>');
    for (const result of [mixedCase, whitespace, entityEncoded]) {
      expect(result.includes("href")).toBe(false);
      expect(/javascript\s*:/i.test(result)).toBe(false);
    }
  });

  test("moderate profile allows safe links and formatting tags through", () => {
    const sanitizer = new InputSanitizer("moderate");
    const result = sanitizer.sanitizeHTML('<a href="https://example.com">safe</a> <strong>bold</strong>');
    expect(result).toBe('<a href="https://example.com">safe</a> <strong>bold</strong>');
  });

  test("strict profile blocks tags not anticipated by a fixed allowlist (e.g. custom/unknown tags)", () => {
    const sanitizer = new InputSanitizer("strict");
    const result = sanitizer.sanitizeHTML("<x-evil onclick=alert(1)>text</x-evil>");
    expect(result).toBe("text");
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