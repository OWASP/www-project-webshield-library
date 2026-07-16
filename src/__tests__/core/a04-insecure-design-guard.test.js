import { describe, expect, test } from "@jest/globals";
import { DesignChecklist, ThreatModelGuard } from "../../core/a04-insecure-design-guard/index.js";

describe("A04 insecure design guard", () => {
  test("validates secure state transitions", () => {
    const guard = new ThreatModelGuard({ transitions: { draft: ["review"], review: ["approved"] } });
    expect(guard.validateTransition("draft", "review").valid).toBe(true);
    expect(guard.validateTransition("draft", "approved").valid).toBe(false);
  });

  test("evaluates abuse rules and returns structured violations", () => {
    const guard = new ThreatModelGuard({
      abuseRules: [
        { id: "rate-limit", message: "Too many attempts", check: (context) => context.attempts < 5 },
        { id: "mfa", message: "MFA required", check: (context) => context.mfaVerified === true }
      ]
    });

    expect(guard.evaluateAbuseCase({ attempts: 8, mfaVerified: false })).toEqual({
      valid: false,
      violations: [
        { id: "rate-limit", message: "Too many attempts" },
        { id: "mfa", message: "MFA required" }
      ]
    });
  });

  test("checklist detects missing controls", () => {
    const checklist = new DesignChecklist(["2fa", "audit-log"]);
    const result = checklist.validate(["2fa"]);
    expect(result.valid).toBe(false);
    expect(result.missing).toContain("audit-log");
  });
});