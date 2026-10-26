import { randomBytes } from "node:crypto";
import { CryptoManager, SecurityError, SecurityErrorCode } from "@owasp-webshield/core";

/** ISO 13616 IBAN check: country code, check digits, then the mod-97 checksum. */
export function isValidIban(value) {
  const iban = String(value).replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(iban)) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    const digits = /\d/.test(char) ? char : String(char.charCodeAt(0) - 55);
    for (const digit of digits) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

export const maskIban = (iban) => `${iban.slice(0, 2)}•• •••• ${iban.slice(-4)}`;

/**
 * A02: payout accounts encrypted at rest with AES-256-GCM (`CryptoManager`).
 * Only the masked form is shown to the employee; finance decrypts it to pay a
 * claim, and every decryption is audited.
 *
 * The key comes from BANK_DETAILS_KEY (32 bytes, base64). Without it the demo
 * uses a random key per process, so saved details don't survive a restart.
 * In production, load it from a KMS or secret store.
 */
export function createBankDetailsStore({ key = loadKey() } = {}) {
  const crypto = new CryptoManager();
  const records = new Map();

  return {
    save(userId, rawIban) {
      const iban = String(rawIban).replace(/\s+/g, "").toUpperCase();
      if (!isValidIban(iban)) {
        throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "That isn't a valid IBAN", {
          errors: [{ field: "iban", code: "pattern", message: "That isn't a valid IBAN" }]
        });
      }
      records.set(userId, { masked: maskIban(iban), payload: crypto.encrypt(iban, key) });
      return maskIban(iban);
    },

    masked(userId) {
      return records.get(userId)?.masked ?? null;
    },

    /** The full IBAN. Callers must check `view:bank-details` and log the access. */
    reveal(userId) {
      const record = records.get(userId);
      return record ? crypto.decrypt(record.payload, key) : null;
    },

    // For tests: what is actually held in memory.
    raw(userId) {
      return records.get(userId)?.payload;
    }
  };
}

function loadKey() {
  const configured = process.env.BANK_DETAILS_KEY;
  if (!configured) return randomBytes(32);
  const key = Buffer.from(configured, "base64");
  if (key.length !== 32) throw new Error("BANK_DETAILS_KEY must be 32 bytes, base64-encoded");
  return key;
}
