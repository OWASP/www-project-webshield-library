import { describe, expect, test } from "@jest/globals";
import { DesignChecklist, ThreatModelGuard } from "../../core/a04-insecure-design-guard/index.js";

describe("A04 insecure design guard", () => {
  test("validates secure state transitions", () => {
    const guard = new ThreatModelGuard({ transitions: { draft: ["review"], review: ["approved"] } });
    expect(guard.validateTransition("draft", "review").valid).toBe(true);
    expect(guard.validateTransition("draft", "approved").valid).toBe(false);
  });

  test("checklist detects missing controls", () => {
    const checklist = new DesignChecklist(["2fa", "audit-log"]);
    const result = checklist.validate(["2fa"]);
    expect(result.valid).toBe(false);
    expect(result.missing).toContain("audit-log");
  });
});