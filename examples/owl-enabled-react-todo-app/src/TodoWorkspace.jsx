import React from "react";
import {
  PermissionGate,
  SanitizedText,
  SecurityAlert,
  useACL,
  useAuth,
  useAuthToken,
  useInputSanitizer,
  usePermission,
  useSafeFetcher,
  useSecurityMonitoring,
  useThreatModelGuard,
  withSecurityHeaders
} from "@owasp-core/owl-react";
import { security, SecretPolicy } from "./security";

const WORKFLOW_CONFIG = {
  transitions: {
    todo: ["in_progress"],
    in_progress: ["blocked", "done", "todo"],
    blocked: ["in_progress"],
    done: []
  },
  abuseRules: [
    { id: "title_too_long", message: "Title must stay under 80 characters", check: (ctx) => ctx.title.length <= 80 },
    { id: "notes_too_long", message: "Notes must stay under 300 characters", check: (ctx) => ctx.notes.length <= 300 }
  ]
};

const seedTodos = [
  {
    id: "T-101",
    title: "Finalize onboarding checklist",
    notes: "Include account setup docs and remove stale script tag <script>alert(1)</script>",
    status: "todo",
    assignee: "riley",
    priority: "high",
    attachmentUrl: "https://cdn.example.com/templates/onboarding-v2.md"
  },
  {
    id: "T-102",
    title: "Prepare sprint retro board",
    notes: "Collect wins, blockers, and action items from each team",
    status: "in_progress",
    assignee: "avery",
    priority: "medium",
    attachmentUrl: "http://127.0.0.1/notes"
  },
  {
    id: "T-103",
    title: "Publish customer release notes",
    notes: "Draft for review with product and support",
    status: "blocked",
    assignee: "riley",
    priority: "low",
    attachmentUrl: "https://docs.example.com/release-notes/draft"
  }
];

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

export default function TodoWorkspace() {
  const { session } = useAuth();
  const token = useAuthToken();
  const aclManager = useACL();
  const canRead = usePermission("read", "todos");
  const canWrite = usePermission("write", "todos");
  const canDelete = usePermission("delete", "todos");
  const rawDeleteDecision = aclManager.evaluate("todos", "delete");
  const sanitizer = useInputSanitizer("strict");
  const { logger, events } = useSecurityMonitoring();
  const modelGuard = useThreatModelGuard(WORKFLOW_CONFIG);
  const safeFetcher = useSafeFetcher({}, async (url) => ({
    ok: true,
    json: async () => ({ ok: true, url })
  }));

  const [todos, setTodos] = React.useState(seedTodos);
  const [selectedId, setSelectedId] = React.useState(seedTodos[0].id);
  const [draftTitle, setDraftTitle] = React.useState(seedTodos[0].title);
  const [draftNotes, setDraftNotes] = React.useState(seedTodos[0].notes);
  const [draftAttachmentUrl, setDraftAttachmentUrl] = React.useState(seedTodos[0].attachmentUrl);
  const [createTitle, setCreateTitle] = React.useState("");
  const [formAlert, setFormAlert] = React.useState(null);
  const [apiTrace, setApiTrace] = React.useState(null);
  const [outboundTrace, setOutboundTrace] = React.useState("No attachment check yet");

  const selectedTodo = todos.find((item) => item.id === selectedId) || todos[0];
  const sanitizedTitle = sanitizer.sanitizeHTML(draftTitle);
  const sanitizedNotes = sanitizer.sanitizeHTML(draftNotes);
  const entropy = SecretPolicy.minimumEntropyBits(token || "");
  const abuseCheck = modelGuard.evaluateAbuseCase({ title: sanitizedTitle, notes: sanitizedNotes });

  React.useEffect(() => {
    if (!selectedTodo) return;
    setDraftTitle(selectedTodo.title);
    setDraftNotes(selectedTodo.notes);
    setDraftAttachmentUrl(selectedTodo.attachmentUrl || "");
  }, [selectedTodo]);

  function emitActivity(type, details = {}) {
    logger?.info(type, details);
    events?.emit("activity", {
      ts: new Date().toISOString(),
      type,
      actor: session?.userId || "unknown",
      details
    });
  }

  async function syncTodos() {
    try {
      const response = await security.apiClient.request(
        "/todos/sync",
        withSecurityHeaders({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ count: todos.length, updatedBy: session?.userId })
        })
      );
      setApiTrace(response.data);
      emitActivity("todos_synced", { count: todos.length });
    } catch (error) {
      setFormAlert(`Sync blocked: ${error.message}`);
      emitActivity("todos_sync_blocked", { reason: error.message });
    }
  }

  async function validateAttachment() {
    try {
      const response = await safeFetcher.fetch(draftAttachmentUrl);
      await response.json();
      setOutboundTrace(`Allowed target: ${draftAttachmentUrl}`);
      emitActivity("attachment_validated", { todoId: selectedTodo.id, target: draftAttachmentUrl });
    } catch (error) {
      setOutboundTrace(`Blocked target: ${error.message}`);
      logger?.warn("attachment_validation_blocked", { target: draftAttachmentUrl, reason: error.message });
    }
  }

  async function runBlockedUrlProbe() {
    try {
      await safeFetcher.fetch("http://127.0.0.1/admin");
      setOutboundTrace("Unexpected allow for private target");
    } catch (error) {
      setOutboundTrace(`Blocked private target: ${error.message}`);
    }
  }

  function saveTodoEdits() {
    if (!canWrite.allowed || !selectedTodo) return;
    if (!abuseCheck.valid) {
      setFormAlert(abuseCheck.violations.map((v) => v.message).join(" "));
      emitActivity("todo_save_blocked", { reason: abuseCheck.violations.map((v) => v.id).join(",") });
      return;
    }
    setFormAlert(null);
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
      setFormAlert(`Cannot move "${selectedTodo.status}" to "${nextStatus}" (${check.reason}).`);
      emitActivity("todo_transition_blocked", { todoId: selectedTodo.id, from: selectedTodo.status, to: nextStatus });
      return;
    }
    setFormAlert(null);
    setTodos((prev) =>
      prev.map((item) => (item.id === selectedTodo.id ? { ...item, status: nextStatus } : item))
    );
    emitActivity("todo_transitioned", { todoId: selectedTodo.id, from: selectedTodo.status, to: nextStatus });
  }

  function createTodo() {
    if (!canWrite.allowed) return;
    const validation = security.inputValidator.validateSchema(
      { title: createTitle },
      { title: { required: true, type: "string", minLength: 3, maxLength: 80 } }
    );
    if (!validation.valid) {
      setFormAlert(validation.errors.map((e) => e.message).join(" "));
      return;
    }
    setFormAlert(null);
    const title = sanitizer.sanitizeHTML(createTitle);
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
        <SecurityAlert level="error" message="Your current role cannot read todos." />
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

  return (
    <>
      <section className="panel md:col-span-2 surface-hero">
        <p className="section-kicker">Todo Workspace</p>
        <h2 className="panel-title text-xl">Team Task Tracker</h2>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Every action below — create, edit, transition, sync, delete, attach a link — runs
          through an OWL security control before it takes effect.
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
        {formAlert ? (
          <div className="mt-4">
            <SecurityAlert level="warn" message={formAlert} />
          </div>
        ) : null}
      </section>

      <section className="panel">
        <div className="flex items-center justify-between">
          <h3 className="panel-title">Task Backlog</h3>
          <span className="chip">{todos.length} total</span>
        </div>
        <div className="mt-3 space-y-2 rounded-xl bg-slate-100/80 p-3">
          <input
            className="input"
            placeholder="New task title (validated + sanitized)"
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
                  <p className="font-semibold text-slate-800">
                    {item.id} · <SanitizedText profile="strict" html={item.title} />
                  </p>
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
        <h3 className="panel-title">Workspace Access (A01 / A02 / A07)</h3>
        <p className="mt-3 text-sm">User: <strong>{session?.userId}</strong> ({session?.roles?.[0]})</p>
        <p className="mt-2 text-sm">Access token entropy estimate: <strong>{entropy} bits</strong></p>
        <p className="mt-2 text-sm">Read permission (usePermission): <strong>{String(canRead.allowed)}</strong></p>
        <p className="mt-2 text-sm">Write permission (usePermission): <strong>{String(canWrite.allowed)}</strong></p>
        <p className="mt-2 text-sm">
          Delete permission (usePermission, RBAC+ACL combined): <strong>{String(canDelete.allowed)}</strong>
        </p>
        <p className="mt-1 text-xs text-slate-500">
          Raw ACL decision (useACL, delete:todos): <strong>{rawDeleteDecision.effect}</strong> — this deny
          wins over any role grant, which is why delete stays blocked below regardless of role.
        </p>
      </section>

      <section className="panel">
        <div className="flex items-center justify-between">
          <h3 className="panel-title">Task Editor (A03 / A04)</h3>
          <span className="chip">{selectedTodo?.id}</span>
        </div>
        <input className="input mt-3" value={draftTitle} onChange={(e) => setDraftTitle(e.target.value)} />
        <textarea className="input mt-2 h-24" value={draftNotes} onChange={(e) => setDraftNotes(e.target.value)} />
        <p className="mt-2 text-xs text-slate-500">sanitized title preview (SanitizedText)</p>
        <p className="mt-1 rounded-md bg-slate-100 p-2 text-sm">
          <SanitizedText profile="strict" html={draftTitle} />
        </p>
        <p className="mt-2 text-xs text-slate-500">sanitized notes preview (useInputSanitizer)</p>
        <p className="mt-1 rounded-md bg-slate-100 p-2 text-sm">{sanitizedNotes}</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <button className="btn" onClick={saveTodoEdits} disabled={!canWrite.allowed} type="button">Save Task</button>
          <button className="btn" onClick={() => transitionTodo("in_progress")} disabled={!canWrite.allowed} type="button">Start</button>
          <button className="btn" onClick={() => transitionTodo("blocked")} disabled={!canWrite.allowed} type="button">Block</button>
          <button className="btn" onClick={() => transitionTodo("done")} disabled={!canWrite.allowed} type="button">Complete</button>
        </div>
        <p className="mt-3 text-sm">Current status: <strong>{selectedTodo?.status}</strong></p>
        <p className="mt-2 text-sm">Input abuse checks (useThreatModelGuard): <strong>{String(abuseCheck.valid)}</strong></p>

        <div className="mt-4 border-t border-slate-200 pt-3">
          <PermissionGate
            action="delete"
            resource="todos"
            fallback={
              <p className="text-xs text-rose-700">
                Delete is blocked by ACL policy (deny-override) — PermissionGate hides the button entirely.
              </p>
            }
          >
            <button className="btn bg-rose-700 hover:bg-rose-600" onClick={deleteTodo} type="button">
              Delete Task
            </button>
          </PermissionGate>
        </div>
      </section>

      <section className="panel">
        <h3 className="panel-title">Sync + Attachment Validation (A08 / A10)</h3>
        <p className="mt-2 text-xs text-slate-500">attachment URL</p>
        <input
          className="input mt-1"
          value={draftAttachmentUrl}
          onChange={(e) => setDraftAttachmentUrl(e.target.value)}
        />
        <div className="mt-3 flex flex-wrap gap-2">
          <button className="btn" onClick={() => void syncTodos()} type="button">
            Sync Tasks (CSRF + auth headers)
          </button>
          <button className="btn" onClick={() => void validateAttachment()} type="button">
            Validate Attachment (SSRF guard)
          </button>
          <button className="btn bg-rose-700 hover:bg-rose-600" onClick={() => void runBlockedUrlProbe()} type="button">
            Probe 127.0.0.1 (should block)
          </button>
        </div>
        <p className="mt-3 text-sm">{outboundTrace}</p>
        <pre className="code-block mt-3">{JSON.stringify(apiTrace, null, 2)}</pre>
      </section>
    </>
  );
}
