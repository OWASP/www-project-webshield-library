import { describe, expect, test } from "@jest/globals";
import { EventEmitter, SecurityLogger } from "../../core/a09-logging-monitoring/index.js";

describe("A09 logging and monitoring", () => {
  test("event emitter subscribes and emits", () => {
    const emitter = new EventEmitter();
    let received = null;
    emitter.on("auth", (payload) => {
      received = payload;
    });
    emitter.emit("auth", { ok: true });
    expect(received.ok).toBe(true);
  });

  test("event emitter unsubscribes listeners", () => {
    const emitter = new EventEmitter();
    let calls = 0;
    const unsubscribe = emitter.on("auth", () => {
      calls += 1;
    });

    unsubscribe();
    emitter.emit("auth", { ok: true });

    expect(calls).toBe(0);
  });

  test("logger redacts sensitive values", () => {
    let output = null;
    const logger = new SecurityLogger({ sink: (entry) => (output = entry) });
    logger.info("login", { password: "secret", token: "abc", keep: "x" });
    expect(output.details.password).toBe("[REDACTED]");
    expect(output.details.token).toBe("[REDACTED]");
    expect(output.details.keep).toBe("x");
  });

  test("logger preserves level and redacts nested sensitive values", () => {
    let output = null;
    const logger = new SecurityLogger({ sink: (entry) => (output = entry) });

    logger.error("auth.failed", {
      request: { authorization: "Bearer token" },
      cookies: [{ cookie: "session=1" }]
    });

    expect(output.level).toBe("error");
    expect(output.details.request.authorization).toBe("[REDACTED]");
    expect(output.details.cookies).toBe("[REDACTED]");
  });
});