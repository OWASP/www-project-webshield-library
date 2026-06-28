import React from "react";
import { SecretPolicy } from "@owl/core/src/core/a02-crypto-integrity/SecretPolicy.js";

export default function A02Page() {
  const [secret, setSecret] = React.useState("api-key-demo-value");
  const [issuedAt, setIssuedAt] = React.useState(Date.now() - 1000 * 60 * 60 * 24 * 120);

  const entropy = SecretPolicy.minimumEntropyBits(secret);
  const strongEnough = SecretPolicy.isEntropySufficient(secret, 60);
  const rotationExceeded = SecretPolicy.isRotationWindowExceeded(issuedAt, 1000 * 60 * 60 * 24 * 90);

  function rotateNow() {
    setIssuedAt(Date.now());
  }

  return (
    <>
      <section className="panel">
        <h2 className="panel-title">A02 Cryptographic Failures</h2>
        <p className="mt-2 text-sm text-slate-600">
          Browser-safe demo of secret entropy and rotation controls via OWL SecretPolicy.
        </p>
        <input className="input mt-4" value={secret} onChange={(e) => setSecret(e.target.value)} />
        <button className="btn mt-4" onClick={rotateNow} type="button">Rotate Secret Timestamp</button>
      </section>
      <section className="panel">
        <h3 className="panel-title">Policy Checks</h3>
        <ul className="mt-3 space-y-2 text-sm">
          <li>Entropy bits: <strong>{entropy}</strong></li>
          <li>Meets minimum entropy: <strong>{String(strongEnough)}</strong></li>
          <li>Rotation window exceeded: <strong>{String(rotationExceeded)}</strong></li>
        </ul>
        <p className="mt-3 text-xs text-slate-500">
          Use CryptoManager and KDF adapters in server or edge runtime for full encryption workflows.
        </p>
      </section>
    </>
  );
}
