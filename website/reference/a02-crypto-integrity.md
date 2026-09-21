# A02 — Cryptographic Failures

Key derivation, authenticated encryption, and secret-strength policy in one module. `CryptoManager` uses AES-256-GCM and a pluggable KDF adapter (PBKDF2 built in, Argon2 pluggable).

::: warning Node-only
This module imports Node's built-in `node:crypto`. It runs fine in Node.js and in the React adapter's hooks when your app is server-rendered or Node-bundled, but bundling it directly into a browser build requires polyfilling `node:crypto` — see the [FAQ](/faq#can-i-use-owl-in-a-browser-bundle).
:::

## Core API (`@owasp-js/owl`)

```js
import {
  Argon2Adapter,
  CryptoManager,
  PBKDF2Adapter,
  SecretPolicy,
  generateSalt
} from "@owasp-js/owl";

const salt = generateSalt();
const crypto = new CryptoManager({
  kdfAdapter: new PBKDF2Adapter({ iterations: 210000, keyLength: 32, digest: "sha256" })
});

const { key } = crypto.deriveKey("correct-horse-battery-staple", salt);
const encrypted = crypto.encrypt("sensitive payload", key);
const decrypted = crypto.decrypt(encrypted, key);

const argon2 = new Argon2Adapter({
  deriveFn: (_password, deriveSalt) => Buffer.concat([deriveSalt, Buffer.alloc(32)]).subarray(0, 32)
});
argon2.deriveKey("password", salt, { memoryCost: 19456 });

SecretPolicy.isEntropySufficient("correct-horse-battery-staple", 60);
SecretPolicy.isRotationWindowExceeded(Date.now() - 86_500_000, 86_400_000);
```

- `Argon2Adapter` takes a `deriveFn` you supply — OWL does not bundle an Argon2 implementation itself, keeping the core dependency-free.
- `SecretPolicy.minimumEntropyBits()` / `isEntropySufficient()` estimate entropy from distinct-character count × bits-per-symbol implied by the character classes present, not raw length — see [CHANGELOG](/changelog) for the 1.0.3 fix to this estimate.

## React Adapter (`@owasp-js/owl-react`)

```jsx
import React from "react";
import { useCryptoManager } from "@owasp-js/owl-react";

export function PasswordPreview() {
  const crypto = useCryptoManager();

  function handleDerive() {
    const { key, salt } = crypto.deriveKey("correct-horse-battery-staple");
    console.log(key.length, salt.toString("base64"));
  }

  return <button onClick={handleDerive}>Derive key</button>;
}
```
