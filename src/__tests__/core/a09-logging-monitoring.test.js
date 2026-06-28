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

  test("logger redacts sensitive values", () => {
    let output = null;
    const logger = new SecurityLogger({ sink: (entry) => (output = entry) });
    logger.info("login", { password: "secret", token: "abc", keep: "x" });
    expect(output.details.password).toBe("[REDACTED]");
    expect(output.details.token).toBe("[REDACTED]");
    expect(output.details.keep).toBe("x");
  });
});