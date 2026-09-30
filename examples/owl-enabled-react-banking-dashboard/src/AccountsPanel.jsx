import React from "react";
import { usePermission, useSecurityMonitoring, withSecurityHeaders } from "@owasp-webshield/react";
import { ACCOUNTS, CryptoManager, security } from "./security";

const currency = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" });

export default function AccountsPanel() {
  const canRead = usePermission("read", "accounts");
  const canReveal = usePermission("reveal", "account-number");
  const { logger, events } = useSecurityMonitoring();
  const [revealed, setRevealed] = React.useState({});
  const [revealError, setRevealError] = React.useState(null);
  const [cryptoResult, setCryptoResult] = React.useState(null);

  function emitActivity(type, details = {}) {
    logger?.info(type, details);
    events?.emit("activity", { ts: new Date().toISOString(), type, actor: "current-user", details });
  }

  async function revealAccount(accountId) {
    setRevealError(null);
    try {
      const response = await security.apiClient.request(
        "/vault/reveal",
        withSecurityHeaders({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ accountId })
        })
      );
      if (response.data?.fullNumber) {
        setRevealed((prev) => ({ ...prev, [accountId]: response.data.fullNumber }));
        emitActivity("account_number_revealed", { accountId });
      } else {
        setRevealError(`Vault lookup failed for ${accountId}`);
      }
    } catch (error) {
      setRevealError(`Reveal blocked: ${error.message}`);
      emitActivity("account_number_reveal_blocked", { accountId, reason: error.message });
    }
  }

  function hideAccount(accountId) {
    setRevealed((prev) => {
      const next = { ...prev };
      delete next[accountId];
      return next;
    });
  }

  function tryBrowserEncryption() {
    try {
      const manager = new CryptoManager();
      const { key } = manager.deriveKey("demo-passphrase");
      const ciphertext = manager.encrypt("4400 1234 5678 4821", key);
      setCryptoResult({ ok: true, ciphertext });
    } catch (error) {
      setCryptoResult({ ok: false, message: error.message });
      emitActivity("browser_crypto_manager_blocked", { reason: error.message });
    }
  }

  if (!canRead.allowed) {
    return (
      <section className="panel md:col-span-2">
        <h2 className="panel-title">Accounts</h2>
        <p role="alert" data-level="error">
          Your current role cannot read accounts.
        </p>
      </section>
    );
  }

  const totalBalance = ACCOUNTS.reduce((sum, account) => sum + account.balance, 0);

  return (
    <>
      <section className="panel md:col-span-2 surface-hero">
        <p className="section-kicker">Accounts (A01 / A02)</p>
        <h2 className="panel-title text-xl">Account Overview</h2>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Every account number below is masked by default. The full number is never held in this
          app&apos;s state — it&apos;s fetched on demand from a CSRF- and auth-protected vault call,
          and every reveal is written to the security audit log.
        </p>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <article className="metric-card">
            <p className="metric-label">Accounts</p>
            <p className="metric-value">{ACCOUNTS.length}</p>
          </article>
          <article className="metric-card">
            <p className="metric-label">Total Balance</p>
            <p className="metric-value text-emerald-700">{currency.format(totalBalance)}</p>
          </article>
          <article className="metric-card">
            <p className="metric-label">Reveal Permission</p>
            <p className="metric-value">{String(canReveal.allowed)}</p>
          </article>
        </div>
        {revealError ? (
          <div className="mt-4">
            <p role="alert" data-level="warn">
              {revealError}
            </p>
          </div>
        ) : null}
      </section>

      <section className="panel md:col-span-2">
        <h3 className="panel-title">Your Accounts</h3>
        <div className="mt-3 space-y-2">
          {ACCOUNTS.map((account) => {
            const isRevealed = Boolean(revealed[account.id]);
            return (
              <div key={account.id} className="list-row border-slate-200 bg-white">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="font-semibold text-slate-800">{account.label}</p>
                    <p className="mt-1 text-xs text-slate-500">{account.type}</p>
                    <p className="mt-2 font-mono text-sm text-slate-700">
                      {isRevealed ? revealed[account.id] : `•••• •••• •••• ${account.last4}`}
                    </p>
                  </div>
                  <div className="flex flex-col items-end gap-2">
                    <p className="text-lg font-bold text-slate-900">{currency.format(account.balance)}</p>
                    {canReveal.allowed ? (
                      isRevealed ? (
                        <button className="btn-ghost" type="button" onClick={() => hideAccount(account.id)}>
                          Hide Number
                        </button>
                      ) : (
                        <button className="btn" type="button" onClick={() => void revealAccount(account.id)}>
                          Reveal Number (vault call)
                        </button>
                      )
                    ) : (
                      <span className="chip">reveal denied for this role</span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section className="panel md:col-span-2">
        <h3 className="panel-title">Browser Crypto Sandbox (A02)</h3>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Real account-number encryption (AES-256-GCM + PBKDF2) only ever runs in a trusted Node
          context — never in the browser. This app&apos;s browser bundle resolves{" "}
          <code>CryptoManager</code> to a same-shaped stub that throws a clear error instead of
          silently falling back to weaker crypto or breaking the build. Try it:
        </p>
        <button className="btn mt-3" type="button" onClick={tryBrowserEncryption}>
          Call CryptoManager.encrypt() right here in the browser
        </button>
        {cryptoResult ? (
          <div className="mt-3">
            {cryptoResult.ok ? (
              <p role="alert" data-level="info">
                Unexpected: encryption succeeded in the browser ({JSON.stringify(cryptoResult.ciphertext)}).
              </p>
            ) : (
              <p role="alert" data-level="warn">
                Correctly refused: {cryptoResult.message}
              </p>
            )}
          </div>
        ) : null}
      </section>
    </>
  );
}
