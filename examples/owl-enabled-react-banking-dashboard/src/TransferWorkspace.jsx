import React from "react";
import {
  PermissionGate,
  SanitizedText,
  useInputSanitizer,
  usePermission,
  useSecurityMonitoring,
  useThreatModelGuard,
  withSecurityHeaders
} from "@owasp-webshield/react";
import { security } from "./security";

const APPROVAL_THRESHOLD = 2000;
const DUAL_CONTROL_THRESHOLD = 10000;
const MAX_TRANSFER = 25000;

const WORKFLOW_CONFIG = {
  transitions: {
    draft: ["otp_requested", "cancelled"],
    otp_requested: ["otp_verified", "cancelled"],
    otp_verified: ["pending_approval", "completed", "cancelled"],
    pending_approval: ["completed", "cancelled"],
    completed: [],
    cancelled: []
  },
  abuseRules: [
    {
      id: "amount_invalid",
      message: `Amount must be between $0.01 and $${MAX_TRANSFER.toLocaleString()}`,
      check: (ctx) => ctx.amount > 0 && ctx.amount <= MAX_TRANSFER
    },
    { id: "memo_too_long", message: "Memo must stay under 140 characters", check: (ctx) => ctx.memo.length <= 140 }
  ]
};

const currency = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" });

const seedTransfers = [
  {
    id: "TRF-9001",
    recipient: "US33-BANK-0099-2231",
    amount: 450,
    memo: "Rent share for July <script>alert(1)</script>",
    status: "completed",
    reference: "TXN-DEMO001"
  },
  {
    id: "TRF-9002",
    recipient: "US33-BANK-0044-7712",
    amount: 4200,
    memo: "Vendor invoice #482",
    status: "pending_approval",
    requiresDualControl: false
  },
  {
    id: "TRF-9003",
    recipient: "US33-BANK-0071-1290",
    amount: 18500,
    memo: "Equipment purchase, batch 3",
    status: "pending_approval",
    requiresDualControl: true
  }
];

function statusBadge(status) {
  if (status === "completed") return "status-pill status-done";
  if (status === "pending_approval") return "status-pill status-pending";
  if (status === "cancelled") return "status-pill status-blocked";
  if (status === "draft") return "status-pill status-draft";
  return "status-pill status-progress";
}

export default function TransferWorkspace() {
  const canCreate = usePermission("create", "transfer");
  const sanitizer = useInputSanitizer("strict");
  const { logger, events } = useSecurityMonitoring();
  const modelGuard = useThreatModelGuard(WORKFLOW_CONFIG);

  const [transfers, setTransfers] = React.useState(seedTransfers);
  const [selectedId, setSelectedId] = React.useState(seedTransfers[0].id);
  const [recipient, setRecipient] = React.useState("");
  const [amount, setAmount] = React.useState("");
  const [memo, setMemo] = React.useState("");
  const [otpInput, setOtpInput] = React.useState("");
  const [formAlert, setFormAlert] = React.useState(null);
  const [apiTrace, setApiTrace] = React.useState(null);

  const selected = transfers.find((item) => item.id === selectedId) || null;
  const sanitizedMemo = sanitizer.sanitizeHTML(memo);

  function emitActivity(type, details = {}) {
    logger?.info(type, details);
    events?.emit("activity", { ts: new Date().toISOString(), type, actor: "current-user", details });
  }

  function updateTransfer(id, patch) {
    setTransfers((prev) => prev.map((item) => (item.id === id ? { ...item, ...patch } : item)));
  }

  function createDraft() {
    if (!canCreate.allowed) return;
    const numericAmount = Number(amount);
    const validation = security.inputValidator.validateSchema(
      { recipient, amount },
      {
        recipient: { required: true, type: "string", minLength: 4, maxLength: 40 },
        amount: { required: true, type: "string", minLength: 1 }
      }
    );
    if (!validation.valid || Number.isNaN(numericAmount)) {
      setFormAlert(
        [...validation.errors.map((e) => e.message), Number.isNaN(numericAmount) ? "Amount must be a number" : null]
          .filter(Boolean)
          .join(" ")
      );
      return;
    }
    const cleanMemo = sanitizer.sanitizeHTML(memo);
    const abuseCheck = modelGuard.evaluateAbuseCase({ amount: numericAmount, memo: cleanMemo });
    if (!abuseCheck.valid) {
      setFormAlert(abuseCheck.violations.map((v) => v.message).join(" "));
      emitActivity("transfer_draft_blocked", { reason: abuseCheck.violations.map((v) => v.id).join(",") });
      return;
    }
    setFormAlert(null);
    const created = {
      id: `TRF-${9100 + transfers.length}`,
      recipient,
      amount: numericAmount,
      memo: cleanMemo,
      status: "draft"
    };
    setTransfers((prev) => [created, ...prev]);
    setSelectedId(created.id);
    setRecipient("");
    setAmount("");
    setMemo("");
    emitActivity("transfer_created", { transferId: created.id, amount: numericAmount });
  }

  function requestOtp() {
    if (!selected) return;
    const check = modelGuard.validateTransition(selected.status, "otp_requested");
    if (!check.valid) {
      setFormAlert(`Cannot request OTP from "${selected.status}" (${check.reason}).`);
      return;
    }
    const code = String(Math.floor(100000 + Math.random() * 900000));
    updateTransfer(selected.id, { status: "otp_requested", otpCode: code });
    setFormAlert(null);
    emitActivity("transfer_otp_requested", { transferId: selected.id });
  }

  function verifyOtp() {
    if (!selected) return;
    if (otpInput !== selected.otpCode) {
      setFormAlert("Incorrect verification code.");
      emitActivity("transfer_otp_failed", { transferId: selected.id });
      return;
    }
    const check = modelGuard.validateTransition(selected.status, "otp_verified");
    if (!check.valid) {
      setFormAlert(`Cannot verify OTP from "${selected.status}" (${check.reason}).`);
      return;
    }
    updateTransfer(selected.id, { status: "otp_verified" });
    setOtpInput("");
    setFormAlert(null);
    emitActivity("transfer_otp_verified", { transferId: selected.id });
  }

  function tryToSkip2fa() {
    if (!selected) return;
    const check = modelGuard.validateTransition(selected.status, "completed");
    setFormAlert(
      check.valid
        ? "Unexpected: guard allowed skipping 2FA."
        : `Blocked as expected: cannot jump "${selected.status}" -> "completed" (${check.reason}).`
    );
    emitActivity("transfer_2fa_skip_attempt_blocked", { transferId: selected.id, from: selected.status });
  }

  async function completeOrQueueApproval() {
    if (!selected) return;
    const requiresDualControl = selected.amount > DUAL_CONTROL_THRESHOLD;
    const requiresApproval = selected.amount > APPROVAL_THRESHOLD;
    const target = requiresApproval ? "pending_approval" : "completed";
    const check = modelGuard.validateTransition(selected.status, target);
    if (!check.valid) {
      setFormAlert(`Cannot move "${selected.status}" to "${target}" (${check.reason}).`);
      return;
    }
    if (target === "pending_approval") {
      updateTransfer(selected.id, { status: "pending_approval", requiresDualControl });
      setFormAlert(null);
      emitActivity("transfer_pending_approval", { transferId: selected.id, requiresDualControl });
      return;
    }
    await executeTransfer(selected.id);
  }

  async function executeTransfer(transferId) {
    try {
      const response = await security.apiClient.request(
        "/transfers/execute",
        withSecurityHeaders({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ transferId })
        })
      );
      setApiTrace(response.data);
      updateTransfer(transferId, { status: "completed", reference: response.data?.reference });
      setFormAlert(null);
      emitActivity("transfer_completed", { transferId, reference: response.data?.reference });
    } catch (error) {
      setFormAlert(`Transfer execution blocked: ${error.message}`);
      emitActivity("transfer_execution_blocked", { transferId, reason: error.message });
    }
  }

  async function approveTransfer() {
    if (!selected) return;
    const check = modelGuard.validateTransition(selected.status, "completed");
    if (!check.valid) {
      setFormAlert(`Cannot approve from "${selected.status}" (${check.reason}).`);
      return;
    }
    try {
      const response = await security.apiClient.request(
        "/transfers/approve",
        withSecurityHeaders({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ transferId: selected.id })
        })
      );
      setApiTrace(response.data);
      updateTransfer(selected.id, { status: "completed", reference: `TXN-${selected.id}` });
      emitActivity("transfer_approved", { transferId: selected.id });
    } catch (error) {
      setFormAlert(`Approval blocked: ${error.message}`);
    }
  }

  function cancelTransfer() {
    if (!selected) return;
    const check = modelGuard.validateTransition(selected.status, "cancelled");
    if (!check.valid) {
      setFormAlert(`Cannot cancel from "${selected.status}" (${check.reason}).`);
      return;
    }
    updateTransfer(selected.id, { status: "cancelled" });
    emitActivity("transfer_cancelled", { transferId: selected.id });
  }

  if (!canCreate.allowed) {
    return (
      <section className="panel md:col-span-2">
        <h2 className="panel-title">Transfer</h2>
        <p role="alert" data-level="error">
          Your current role cannot create transfers.
        </p>
      </section>
    );
  }

  const statusStats = transfers.reduce((acc, item) => {
    acc[item.status] = (acc[item.status] || 0) + 1;
    return acc;
  }, {});

  return (
    <>
      <section className="panel md:col-span-2 surface-hero">
        <p className="section-kicker">Transfer Workspace (A01 / A03 / A04 / A08)</p>
        <h2 className="panel-title text-xl">2FA-Guarded Money Movement</h2>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Every transfer walks a strict draft &rarr; OTP requested &rarr; OTP verified &rarr;
          (pending approval &rarr;) completed state machine. Skipping a step is rejected by{" "}
          <code>ThreatModelGuard</code>, not just hidden by the UI.
        </p>
        <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <article className="metric-card">
            <p className="metric-label">Draft</p>
            <p className="metric-value">{statusStats.draft || 0}</p>
          </article>
          <article className="metric-card">
            <p className="metric-label">In 2FA</p>
            <p className="metric-value text-amber-700">{(statusStats.otp_requested || 0) + (statusStats.otp_verified || 0)}</p>
          </article>
          <article className="metric-card">
            <p className="metric-label">Pending Approval</p>
            <p className="metric-value text-sky-700">{statusStats.pending_approval || 0}</p>
          </article>
          <article className="metric-card">
            <p className="metric-label">Completed</p>
            <p className="metric-value text-emerald-700">{statusStats.completed || 0}</p>
          </article>
        </div>
        {formAlert ? (
          <div className="mt-4">
            <p role="alert" data-level="warn">
              {formAlert}
            </p>
          </div>
        ) : null}
      </section>

      <section className="panel">
        <div className="flex items-center justify-between">
          <h3 className="panel-title">New Transfer</h3>
          <span className="chip">{transfers.length} total</span>
        </div>
        <div className="mt-3 space-y-2 rounded-xl bg-slate-100/80 p-3">
          <input className="input" placeholder="Recipient account (IBAN-style)" value={recipient} onChange={(e) => setRecipient(e.target.value)} />
          <input className="input" placeholder="Amount (USD)" value={amount} onChange={(e) => setAmount(e.target.value)} />
          <textarea className="input h-20" placeholder="Memo (sanitized)" value={memo} onChange={(e) => setMemo(e.target.value)} />
          <p className="text-xs text-slate-500">sanitized memo preview</p>
          <p className="rounded-md bg-white p-2 text-sm">{sanitizedMemo || "—"}</p>
          <button className="btn" onClick={createDraft} disabled={!canCreate.allowed} type="button">
            Create Draft
          </button>
        </div>
        <div className="mt-3 space-y-2">
          {transfers.map((item) => (
            <button
              key={item.id}
              className={`list-row ${item.id === selectedId ? "border-owl-600 bg-owl-50 shadow-sm" : "border-slate-200 bg-white"}`}
              onClick={() => setSelectedId(item.id)}
              type="button"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-semibold text-slate-800">
                    {item.id} &middot; {currency.format(item.amount)}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">to {item.recipient}</p>
                </div>
                <span className={statusBadge(item.status)}>{item.status.replace(/_/g, " ")}</span>
              </div>
            </button>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="flex items-center justify-between">
          <h3 className="panel-title">Transfer Detail</h3>
          <span className="chip">{selected?.id}</span>
        </div>
        {!selected ? (
          <p className="mt-3 text-sm text-slate-500">Select a transfer.</p>
        ) : (
          <>
            <p className="mt-3 text-sm">
              Status: <strong className={statusBadge(selected.status)}>{selected.status.replace(/_/g, " ")}</strong>
            </p>
            <p className="mt-2 text-sm">Amount: <strong>{currency.format(selected.amount)}</strong></p>
            <p className="mt-1 text-sm">Recipient: <strong>{selected.recipient}</strong></p>
            <p className="mt-2 text-xs text-slate-500">memo (SanitizedText)</p>
            <p className="mt-1 rounded-md bg-slate-100 p-2 text-sm">
              <SanitizedText profile="strict" html={selected.memo} />
            </p>

            {selected.status === "draft" ? (
              <div className="mt-4 flex flex-wrap gap-2">
                <button className="btn" onClick={requestOtp} type="button">Request OTP</button>
                <button className="btn-ghost" onClick={tryToSkip2fa} type="button">Try to skip 2FA (should be blocked)</button>
              </div>
            ) : null}

            {selected.status === "otp_requested" ? (
              <div className="mt-4 space-y-2">
                <p className="text-xs text-slate-500">Demo OTP (would arrive via SMS in production): <strong>{selected.otpCode}</strong></p>
                <input className="input" placeholder="Enter 6-digit code" value={otpInput} onChange={(e) => setOtpInput(e.target.value)} />
                <div className="flex flex-wrap gap-2">
                  <button className="btn" onClick={verifyOtp} type="button">Verify OTP</button>
                  <button className="btn-ghost" onClick={tryToSkip2fa} type="button">Try to skip 2FA (should be blocked)</button>
                </div>
              </div>
            ) : null}

            {selected.status === "otp_verified" ? (
              <div className="mt-4">
                <p className="text-xs text-slate-500">
                  {selected.amount > APPROVAL_THRESHOLD
                    ? `Amount exceeds $${APPROVAL_THRESHOLD.toLocaleString()} — will route to approval instead of completing immediately.`
                    : "Under approval threshold — completes immediately."}
                </p>
                <button className="btn mt-2" onClick={() => void completeOrQueueApproval()} type="button">
                  Complete Transfer (CSRF-protected)
                </button>
              </div>
            ) : null}

            {selected.status === "pending_approval" ? (
              <div className="mt-4">
                {selected.requiresDualControl ? (
                  <PermissionGate
                    action="approve"
                    resource="large-transfer"
                    fallback={
                      <p className="text-xs text-rose-700">
                        Blocked by maker-checker dual control: this transfer is above the
                        ${DUAL_CONTROL_THRESHOLD.toLocaleString()} ceiling, and an ACL policy denies
                        self-approval for every role, admin included. Requires an out-of-band approval
                        outside this app.
                      </p>
                    }
                  >
                    <button className="btn" onClick={() => void approveTransfer()} type="button">Approve &amp; Complete</button>
                  </PermissionGate>
                ) : (
                  <PermissionGate
                    action="approve"
                    resource="transfer"
                    fallback={<p className="text-xs text-rose-700">Your role cannot approve transfers.</p>}
                  >
                    <button className="btn" onClick={() => void approveTransfer()} type="button">Approve &amp; Complete</button>
                  </PermissionGate>
                )}
              </div>
            ) : null}

            {selected.status === "completed" ? (
              <p className="mt-4 text-sm text-emerald-700">Completed{selected.reference ? ` — ${selected.reference}` : ""}.</p>
            ) : null}

            {!["completed", "cancelled"].includes(selected.status) ? (
              <div className="mt-4 border-t border-slate-200 pt-3">
                <button className="btn-ghost hover:border-rose-200 hover:bg-rose-50 hover:text-rose-700" onClick={cancelTransfer} type="button">
                  Cancel Transfer
                </button>
              </div>
            ) : null}
          </>
        )}
      </section>

      <section className="panel md:col-span-2">
        <h3 className="panel-title">Last API Trace (A08)</h3>
        <p className="mt-2 text-xs text-slate-500">CSRF token + bearer auth header are attached automatically by HTTPClient.</p>
        <pre className="code-block mt-3">{JSON.stringify(apiTrace, null, 2)}</pre>
      </section>
    </>
  );
}
