import { timingSafeEqual } from "node:crypto";
import { CryptoManager, SecurityError, SecurityErrorCode } from "@owasp-webshield/core";

// DEMO ONLY: fixed demo accounts with published passwords, so the README can
// list them. A real service loads users from its own store.
export const DEMO_USERS = [
  { id: "u-alice", username: "alice", name: "Alice (reporter)", roles: ["reporter"], password: "owl-demo-reporter" },
  { id: "u-riley", username: "riley", name: "Riley (responder)", roles: ["responder"], password: "owl-demo-responder" },
  { id: "u-ada", username: "ada", name: "Ada (admin)", roles: ["admin"], password: "owl-demo-admin" }
];

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MS = 60_000;

/**
 * A07: password check with
 * - PBKDF2 hashes (`CryptoManager.deriveKey`, 600,000 iterations by default),
 * - one generic error for an unknown user and a wrong password, with a dummy
 *   hash for unknown users so both take the same time (no user enumeration),
 * - a temporary lockout after repeated failures (slows password guessing).
 */
export function createUserStore({ users = DEMO_USERS, kdfIterations, now = () => Date.now() } = {}) {
  const crypto = new CryptoManager(kdfIterations ? { iterations: kdfIterations } : {});
  const records = new Map();
  for (const user of users) {
    const { key, salt } = crypto.deriveKey(user.password);
    records.set(user.username, { id: user.id, name: user.name, roles: user.roles, hash: key, salt });
  }
  const dummy = crypto.deriveKey("dummy-password-for-unknown-users");
  const failures = new Map();

  function invalid() {
    return new SecurityError(SecurityErrorCode.AUTH_REQUIRED, "Invalid username or password");
  }

  return {
    verify(username, password) {
      const attempts = failures.get(username);
      if (attempts && attempts.lockedUntil > now()) {
        throw new SecurityError(SecurityErrorCode.ACCESS_DENIED, "Too many failed sign-ins. Try again in a minute.", {
          lockedUntil: attempts.lockedUntil
        });
      }

      const record = records.get(username);
      const { key } = crypto.deriveKey(password, record ? record.salt : dummy.salt);
      const matches = timingSafeEqual(key, record ? record.hash : dummy.key) && Boolean(record);

      if (!matches) {
        // Reaching this point means any earlier lockout has expired; count afresh after one.
        const previous = attempts && !attempts.lockedUntil ? attempts.count : 0;
        const count = previous + 1;
        failures.set(username, { count, lockedUntil: count >= MAX_FAILED_ATTEMPTS ? now() + LOCKOUT_MS : 0 });
        throw invalid();
      }

      failures.delete(username);
      return { id: record.id, name: record.name, roles: record.roles };
    }
  };
}
