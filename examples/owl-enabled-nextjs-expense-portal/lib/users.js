import { timingSafeEqual } from "node:crypto";
import { CryptoManager, SecurityError, SecurityErrorCode } from "@owasp-webshield/core";

// DEMO ONLY: fixed accounts with published passwords, so the README can list
// them. A real portal loads users from its identity provider or database.
export const DEMO_USERS = [
  { id: "u-emma", username: "emma", name: "Emma Ito", team: "platform", roles: ["employee"], password: "owl-demo-employee" },
  { id: "u-omar", username: "omar", name: "Omar Haddad", team: "sales", roles: ["employee"], password: "owl-demo-employee" },
  { id: "u-max", username: "max", name: "Max Weber", team: "platform", roles: ["manager"], password: "owl-demo-manager" },
  { id: "u-fiona", username: "fiona", name: "Fiona Kerr", team: "finance", roles: ["finance"], password: "owl-demo-finance" }
];

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MS = 60_000;

/**
 * A07: password check with
 * - PBKDF2 hashes (`CryptoManager.deriveKey`, 600,000 iterations by default),
 * - one generic error for an unknown user and a wrong password, with a dummy
 *   hash for unknown users so both take the same time (no user enumeration),
 * - a temporary lockout after repeated failures for one account.
 */
export function createUserStore({ users = DEMO_USERS, kdfIterations, now = () => Date.now() } = {}) {
  const crypto = new CryptoManager(kdfIterations ? { iterations: kdfIterations } : {});
  const records = new Map();
  for (const { password, ...user } of users) {
    const { key, salt } = crypto.deriveKey(password);
    records.set(user.username, { ...user, hash: key, salt });
  }
  const dummy = crypto.deriveKey("dummy-password-for-unknown-users");
  const failures = new Map();

  const publicUser = ({ id, name, team, roles }) => ({ id, name, team, roles });

  return {
    verify(username, password) {
      const attempts = failures.get(username);
      if (attempts?.lockedUntil > now()) {
        throw new SecurityError(SecurityErrorCode.ACCESS_DENIED, "Too many failed sign-ins. Try again in a minute.");
      }

      const record = records.get(username);
      const { key } = crypto.deriveKey(password, record ? record.salt : dummy.salt);
      const matches = timingSafeEqual(key, record ? record.hash : dummy.key) && Boolean(record);

      if (!matches) {
        const previous = attempts && !attempts.lockedUntil ? attempts.count : 0;
        const count = previous + 1;
        failures.set(username, { count, lockedUntil: count >= MAX_FAILED_ATTEMPTS ? now() + LOCKOUT_MS : 0 });
        throw new SecurityError(SecurityErrorCode.AUTH_REQUIRED, "Invalid username or password");
      }

      failures.delete(username);
      return publicUser(record);
    },

    byId(id) {
      for (const record of records.values()) if (record.id === id) return publicUser(record);
      return null;
    }
  };
}
