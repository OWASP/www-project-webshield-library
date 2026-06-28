import { describe, expect, test } from "@jest/globals";
import { SSRFGuard } from "../../core/a10-ssrf-defense/index.js";

describe("A10 ssrf defense", () => {
  test("blocks private targets and validates redirect chain", () => {
    const guard = new SSRFGuard({ maxRedirectHops: 2 });
    expect(() => guard.validateUrl("http://127.0.0.1/internal")).toThrow();
    expect(() => guard.validateRedirectChain(["https://a.com", "https://b.com", "https://c.com"])).toThrow();
  });
});