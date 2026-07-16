import { describe, expect, test } from "@jest/globals";
import {
  Argon2Adapter,
  CryptoManager,
  PBKDF2Adapter,
  SecretPolicy
} from "../../core/a02-crypto-integrity/index.js";
import { SecurityErrorCode } from "../../core/error/index.js";

describe("A02 crypto integrity", () => {
  test("encrypts and decrypts with AES-GCM", () => {
    const manager = new CryptoManager();
    const { key } = manager.deriveKey("strong-password");
    const payload = manager.encrypt("hello", key);
    const plain = manager.decrypt(payload, key);
    expect(plain).toBe("hello");
  });

  test("evaluates entropy policy", () => {
    expect(SecretPolicy.isEntropySufficient("abc", 20)).toBe(false);
    expect(SecretPolicy.isEntropySufficient("correct-horse-battery-staple", 20)).toBe(true);
  });

  test("uses PBKDF2 adapter by default", () => {
    const manager = new CryptoManager({ kdfAdapter: new PBKDF2Adapter() });
    const { key } = manager.deriveKey("secret");
    expect(Buffer.isBuffer(key)).toBe(true);
  });

  test("supports Argon2 adapter plugin pattern", () => {
    const argon2 = new Argon2Adapter({
      deriveFn: (_password, salt) => Buffer.concat([salt, Buffer.from("argon2")]).subarray(0, 32)
    });
    const manager = new CryptoManager({ kdfAdapter: argon2 });
    const { key } = manager.deriveKey("secret");
    expect(Buffer.isBuffer(key)).toBe(true);
    expect(key.length).toBe(22);
  });

  test("wraps decrypt failures in a SecurityError", () => {
    const manager = new CryptoManager();
    const { key } = manager.deriveKey("strong-password");
    const payload = manager.encrypt("hello", key);

    expect(() => manager.decrypt({ ...payload, tag: Buffer.alloc(16).toString("base64") }, key)).toThrow(
      expect.objectContaining({ code: SecurityErrorCode.CRYPTO_ERROR })
    );
  });

  test("requires an Argon2 derive plugin when using Argon2Adapter", () => {
    const adapter = new Argon2Adapter();
    expect(() => adapter.deriveKey("secret", Buffer.from("salt"))).toThrow(
      expect.objectContaining({ code: SecurityErrorCode.CRYPTO_ERROR })
    );
  });

  test("treats the entropy threshold boundary as sufficient", () => {
    const secret = "abcd1234";
    const entropy = SecretPolicy.minimumEntropyBits(secret);
    expect(SecretPolicy.isEntropySufficient(secret, entropy)).toBe(true);
  });
});