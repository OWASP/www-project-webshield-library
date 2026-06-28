import React from "react";
import { usePermission } from "@owl/react-adapter/a01-access-control/index.js";
import { useAuth, useAuthToken } from "@owl/react-adapter/a07-auth-session/index.js";
import { useInputSanitizer } from "@owl/react-adapter/a03-injection-defense/index.js";
import { useThreatModelGuard } from "@owl/react-adapter/a04-insecure-design-guard/index.js";
import { useHardeningReport } from "@owl/react-adapter/a05-security-misconfiguration/index.js";
import { useDependencyRiskScanner } from "@owl/react-adapter/a06-vulnerable-components/index.js";
import { useSecurityMonitoring } from "@owl/react-adapter/a09-logging-monitoring/index.js";
import { useSafeFetcher } from "@owl/react-adapter/a10-ssrf-defense/index.js";
import { SecretPolicy } from "@owl/core/src/core/a02-crypto-integrity/SecretPolicy.js";
import { security } from "../security";

const dependencyProvider = {
  async scan() {
    return [
      { name: "legacy-parser", severity: "high", currentVersion: "1.8.2", fixedVersion: "1.8.9" },
      { name: "date-tool", severity: "low", currentVersion: "3.1.0", fixedVersion: "3.1.1" }
    ];
  }
};

const seedTodos = [
  {
    id: "T-101",
    title: "Finalize onboarding checklist",
    notes: "Include account setup docs and remove stale script tag <script>alert(1)</script>",
    status: "todo",
    assignee: "rhea",
    priority: "high",
    attachmentUrl: "https://cdn.example.com/templates/onboarding-v2.md"
  },
  {
    id: "T-102",
    title: "Prepare sprint retro board",
    notes: "Collect wins, blockers, and action items from each team",
    status: "in_progress",
    assignee: "sam",
    priority: "medium",
    attachmentUrl: "http://127.0.0.1/notes"
  },
  {
    id: "T-103",
    title: "Publish customer release notes",
    notes: "Draft for review with product and support",
    status: "blocked",
    assignee: "mina",
    priority: "low",
    attachmentUrl: "https://docs.example.com/release-notes/draft"
  }
];

function statusTone(status) {
  if (status === "done") return "text-emerald-700";
  if (status === "blocked") return "text-rose-700";
  if (status === "in_progress") return "text-amber-700";
  return "text-slate-700";
}

function statusBadge(status) {
  if (status === "done") return "status-pill status-done";
  if (status === "blocked") return "status-pill status-blocked";
  if (status === "in_progress") return "status-pill status-progress";
  return "status-pill status-todo";
}

function priorityBadge(priority) {
  if (priority === "high") return "priority-pill priority-high";
  if (priority === "medium") return "priority-pill priority-medium";
  return "priority-pill priority-low";
}

export default function IntegratedAppPage() {
  const { session } = useAuth();
  const token = useAuthToken();
  const canRead = usePermission("read", "todos");
  const canWrite = usePermission("write", "todos");
  const canDelete = usePermission("delete", "todos");
  const sanitizer = useInputSanitizer("strict");
  const { logger, events } = useSecurityMonitoring();
  const { results, runScan } = useDependencyRiskScanner(dependencyProvider);
  const findings = useHardeningReport({
    debug: false,
    cors: { origin: "self" },
    cookies: { secure: true, sameSite: "Strict" }
  });

  const modelGuard = useThreatModelGuard({
    transitions: {
      todo: ["in_progress"],
      in_progress: ["blocked", "done", "todo"],
      blocked: ["in_progress"],
      done: []
    },
    abuseRules: [
      { id: "title_too_long", message: "Title must stay under 80 chars", check: (ctx) => ctx.title.length <= 80 },
      { id: "notes_too_long", message: "Notes must stay under 300 chars", check: (ctx) => ctx.notes.length <= 300 }
    ]
  });

  const safeFetcher = useSafeFetcher({}, async (url) => ({
    ok: true,
    json: async () => ({ ok: true, url })
  }));

  const [todos, setTodos] = React.useState(seedTodos);
  const [selectedId, setSelectedId] = React.useState(seedTodos[0].id);
  const [draftTitle, setDraftTitle] = React.useState(seedTodos[0].title);
  const [draftNotes, setDraftNotes] = React.useState(seedTodos[0].notes);
  const [draftAttachmentUrl, setDraftAttachmentUrl] = React.useState(seedTodos[0].attachmentUrl);
  const [activityItems, setActivityItems] = React.useState([]);
  const [apiTrace, setApiTrace] = React.useState(null);
  const [outboundTrace, setOutboundTrace] = React.useState("No attachment check yet");
  const [attachmentPreview, setAttachmentPreview] = React.useState(null);
  const [createTitle, setCreateTitle] = React.useState("");
  const [showDetails, setShowDetails] = React.useState(false);

  const selectedTodo = todos.find((item) => item.id === selectedId) || todos[0];
  const sanitizedTitle = sanitizer.sanitizeHTML(draftTitle);
  const sanitizedNotes = sanitizer.sanitizeHTML(draftNotes);
  const entropy = SecretPolicy.minimumEntropyBits(token || "");
  const abuseCheck = modelGuard.evaluateAbuseCase({ title: sanitizedTitle, notes: sanitizedNotes });

  React.useEffect(() => {
    if (!events) return undefined;
    return events.on("todo:event", (payload) => {
      setActivityItems((prev) => [payload, ...prev].slice(0, 8));
    });
  }, [events]);

  React.useEffect(() => {
    if (!selectedTodo) return;
    setDraftTitle(selectedTodo.title);
    setDraftNotes(selectedTodo.notes);
    setDraftAttachmentUrl(selectedTodo.attachmentUrl || "");
  }, [selectedTodo]);

  function emitActivity(type, details = {}) {
    const payload = {
      ts: new Date().toISOString(),
      type,
      actor: session?.userId || "unknown",
      details
    };
    logger?.info(type, details);
    events?.emit("todo:event", payload);
  }

  async function syncTodos() {
    const response = await security.apiClient.request("/todos/sync", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ count: todos.length, updatedBy: session?.userId })
    });
    setApiTrace(response.data);
    emitActivity("todos_synced", { count: todos.length });
  }

  async function validateAttachment() {
    try {
      const response = await safeFetcher.fetch(draftAttachmentUrl);
      const data = await response.json();
      setAttachmentPreview(data);
      setOutboundTrace(`Allowed target: ${draftAttachmentUrl}`);
      emitActivity("attachment_validated", { todoId: selectedTodo.id, target: draftAttachmentUrl });
    } catch (error) {
      setAttachmentPreview(null);
      setOutboundTrace(`Blocked target: ${error.message}`);
      logger?.warn("attachment_validation_blocked", { target: draftAttachmentUrl, reason: error.message });
    }
  }

  function saveTodoEdits() {
    if (!canWrite.allowed || !selectedTodo) return;
    if (!abuseCheck.valid) {
      emitActivity("todo_save_blocked", { reason: abuseCheck.violations.map((v) => v.id).join(",") });
      return;
    }
    setTodos((prev) =>
      prev.map((item) =>
        item.id === selectedTodo.id
          ? { ...item, title: sanitizedTitle, notes: sanitizedNotes, attachmentUrl: draftAttachmentUrl }
          : item
      )
    );
    emitActivity("todo_saved", { todoId: selectedTodo.id });
  }

  function transitionTodo(nextStatus) {
    if (!canWrite.allowed || !selectedTodo) return;
    const check = modelGuard.validateTransition(selectedTodo.status, nextStatus);
    if (!check.valid) {
      emitActivity("todo_transition_blocked", { todoId: selectedTodo.id, from: selectedTodo.status, to: nextStatus });
      return;
    }
    setTodos((prev) =>
      prev.map((item) => (item.id === selectedTodo.id ? { ...item, status: nextStatus } : item))
    );
    emitActivity("todo_transitioned", { todoId: selectedTodo.id, from: selectedTodo.status, to: nextStatus });
  }

  function createTodo() {
    if (!canWrite.allowed) return;
    const title = sanitizer.sanitizeHTML(createTitle);
    if (!title.trim()) return;
    const created = {
      id: `T-${200 + todos.length + 1}`,
      title,
      notes: "",
      status: "todo",
      assignee: session?.userId || "unassigned",
      priority: "medium",
      attachmentUrl: ""
    };
    setTodos((prev) => [created, ...prev]);
    setSelectedId(created.id);
    setCreateTitle("");
    emitActivity("todo_created", { todoId: created.id });
  }

  function deleteTodo() {
    if (!canDelete.allowed || !selectedTodo) return;
    setTodos((prev) => prev.filter((item) => item.id !== selectedTodo.id));
    const remaining = todos.filter((item) => item.id !== selectedTodo.id);
    if (remaining[0]) setSelectedId(remaining[0].id);
    emitActivity("todo_deleted", { todoId: selectedTodo.id });
  }

  if (!canRead.allowed) {
    return (
      <section className="panel md:col-span-2">
        <h2 className="panel-title">Todo Workspace</h2>
        <p className="mt-2 text-sm text-rose-700">Your current role cannot read todos.</p>
      </section>
    );
  }

  const statusStats = todos.reduce(
    (acc, item) => {
      acc[item.status] = (acc[item.status] || 0) + 1;
      return acc;
    },
    { todo: 0, in_progress: 0, blocked: 0, done: 0 }
  );

  const currentTransitionCheck = selectedTodo
    ? modelGuard.validateTransition(selectedTodo.status, "done")
    : { valid: false, reason: "no_selection" };

  const dependencySummary = results.map((item) => `${item.package}:${item.severity}`).join(", ");

  async function runBlockedUrlProbe() {
    try {
      await safeFetcher.fetch("http://127.0.0.1/admin");
      setOutboundTrace("Unexpected allow for private target");
    } catch (error) {
      setOutboundTrace(`Blocked private target: ${error.message}`);
    }
  }

  return (
    <>
      <section className="panel md:col-span-2 surface-hero">
        <p className="section-kicker">Integrated Product App</p>
        <h2 className="panel-title text-xl">Todo Workspace</h2>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          A product-style integrated app where OWL controls are embedded into normal TODO workflows
          like creation, editing, transitions, sync, and collaboration.
        </p>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <article className="metric-card">
            <p className="metric-label">Todo</p>
            <p className="metric-value">{statusStats.todo}</p>
          </article>
          <article className="metric-card">
            <p className="metric-label">In Progress</p>
            <p className="metric-value text-amber-700">{statusStats.in_progress}</p>
          </article>
          <article className="metric-card">
            <p className="metric-label">Blocked</p>
            <p className="metric-value text-rose-700">{statusStats.blocked}</p>
          </article>
          <article className="metric-card">
            <p className="metric-label">Done</p>
            <p className="metric-value text-emerald-700">{statusStats.done}</p>
          </article>
        </div>
      </section>

      <section className="panel">
        <div className="flex items-center justify-between">
          <h3 className="panel-title">Task Backlog</h3>
          <span className="chip">{todos.length} total</span>
        </div>
        <div className="mt-3 space-y-2 rounded-xl bg-slate-100/80 p-3">
          <input
            className="input"
            placeholder="Task title"
            value={createTitle}
            onChange={(e) => setCreateTitle(e.target.value)}
          />
          <button className="btn" onClick={createTodo} disabled={!canWrite.allowed} type="button">
            Add Task
          </button>
        </div>
        <div className="mt-3 space-y-2">
          {todos.map((item) => (
            <button
              key={item.id}
              className={`todo-row ${
                item.id === selectedId ? "border-owl-600 bg-owl-50 shadow-sm" : "border-slate-200 bg-white"
              }`}
              onClick={() => setSelectedId(item.id)}
              type="button"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-semibold text-slate-800">{item.id} · {item.title}</p>
                  <p className="mt-1 text-xs text-slate-500">assignee: {item.assignee}</p>
                </div>
                <div className="flex flex-col items-end gap-1">
                  <span className={statusBadge(item.status)}>{item.status.replace("_", " ")}</span>
                  <span className={priorityBadge(item.priority)}>{item.priority}</span>
                </div>
              </div>
            </button>
          ))}
        </div>
      </section>

      <section className="panel">
        <h3 className="panel-title">Workspace Access</h3>
        <p className="mt-3 text-sm">User: <strong>{session?.userId}</strong></p>
        <p className="mt-2 text-sm">Token entropy estimate (A02): <strong>{entropy}</strong></p>
        <p className="mt-2 text-sm">Read permission (A01/A07): <strong>{String(canRead.allowed)}</strong></p>
        <p className="mt-2 text-sm">Write permission (A01): <strong>{String(canWrite.allowed)}</strong></p>
        <p className="mt-2 text-sm">Delete permission (A01): <strong>{String(canDelete.allowed)}</strong></p>
        <p className="mt-2 text-sm">Hardening findings (A05): <strong>{findings.length}</strong></p>
      </section>

      <section className="panel">
        <div className="flex items-center justify-between">
          <h3 className="panel-title">Task Editor</h3>
          <span className="chip">{selectedTodo?.id}</span>
        </div>
        <input className="input mt-3" value={draftTitle} onChange={(e) => setDraftTitle(e.target.value)} />
        <textarea className="input mt-2 h-24" value={draftNotes} onChange={(e) => setDraftNotes(e.target.value)} />
        <p className="mt-2 text-xs text-slate-500">attachment URL (A10 target)</p>
        <p className="mt-1 rounded-md bg-slate-100 p-2 text-sm break-all">{draftAttachmentUrl || "none"}</p>
        <p className="mt-2 text-xs text-slate-500">sanitized title preview</p>
        <p className="mt-1 rounded-md bg-slate-100 p-2 text-sm">{sanitizedTitle}</p>
        <p className="mt-2 text-xs text-slate-500">sanitized notes preview</p>
        <p className="mt-1 rounded-md bg-slate-100 p-2 text-sm">{sanitizedNotes}</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <button className="btn" onClick={saveTodoEdits} disabled={!canWrite.allowed} type="button">Save Task</button>
          <button className="btn" onClick={() => transitionTodo("in_progress")} disabled={!canWrite.allowed} type="button">Start</button>
          <button className="btn" onClick={() => transitionTodo("blocked")} disabled={!canWrite.allowed} type="button">Block</button>
          <button className="btn" onClick={() => transitionTodo("done")} disabled={!canWrite.allowed} type="button">Complete</button>
          <button className="btn bg-rose-700 hover:bg-rose-600" onClick={deleteTodo} disabled={!canDelete.allowed} type="button">Delete</button>
        </div>
        <p className="mt-3 text-sm">
          Current status: <strong className={statusTone(selectedTodo?.status)}>{selectedTodo?.status}</strong>
        </p>
        <p className="mt-2 text-sm">Done transition check (A04): <strong>{currentTransitionCheck.reason}</strong></p>
        <p className="mt-2 text-sm">Input abuse checks (A04): <strong>{String(abuseCheck.valid)}</strong></p>
      </section>

      <section className="panel">
        <h3 className="panel-title">Sync + Attachment Validation</h3>
        <div className="mt-3 flex flex-wrap gap-2">
          <button className="btn" onClick={() => void syncTodos()} type="button">
            Sync Tasks (A08)
          </button>
          <button className="btn" onClick={() => void validateAttachment()} type="button">
            Validate Attachment (A10)
          </button>
          <button className="btn bg-rose-700 hover:bg-rose-600" onClick={() => void runBlockedUrlProbe()} type="button">
            Probe Blocked URL
          </button>
        </div>
        <p className="mt-3 text-sm">{outboundTrace}</p>
        <pre className="code-block mt-3">{JSON.stringify(attachmentPreview, null, 2)}</pre>
      </section>

      <section className="panel md:col-span-2">
        <button
          className="w-full rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-left"
          onClick={() => setShowDetails((prev) => !prev)}
          type="button"
        >
          <p className="panel-title text-base">Developer Details</p>
          <p className="mt-1 text-xs text-slate-500">
            {showDetails ? "Hide technical telemetry and diagnostics" : "Show technical telemetry and diagnostics"}
          </p>
        </button>

        {showDetails ? (
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <section className="panel">
              <h3 className="panel-title">Platform Health</h3>
              <p className="mt-3 text-sm">Hardening findings (A05): <strong>{findings.length}</strong></p>
              <button className="btn mt-3" onClick={() => void runScan()} type="button">
                Scan Dependencies (A06)
              </button>
              <p className="mt-3 text-sm">Dependency summary: <strong>{dependencySummary || "no scan yet"}</strong></p>
              <pre className="code-block mt-3">{JSON.stringify({ findings, results }, null, 2)}</pre>
            </section>

            <section className="panel">
              <h3 className="panel-title">Sync Trace</h3>
              <pre className="code-block mt-3">{JSON.stringify(apiTrace, null, 2)}</pre>
            </section>

            <section className="panel md:col-span-2">
              <h3 className="panel-title">Activity Timeline</h3>
              <pre className="code-block mt-3">{JSON.stringify(activityItems, null, 2)}</pre>
            </section>
          </div>
        ) : null}
      </section>
    </>
  );
}
