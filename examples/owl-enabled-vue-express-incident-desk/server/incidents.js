import { randomBytes } from "node:crypto";
import { CryptoManager, SecurityError, SecurityErrorCode, ThreatModelGuard } from "@owasp-webshield/core";
import { STATUS_TRANSITIONS } from "../shared/policy.js";

const MAX_OPEN_PER_REPORTER = 10;

/**
 * Incident store with:
 * - A04: the lifecycle (`ThreatModelGuard` transitions) and an abuse-case rule
 *   that caps how many open incidents one person can file;
 * - A02: private notes encrypted at rest with AES-256-GCM (`CryptoManager`).
 *   The key is random per process here; in production it comes from a KMS or
 *   secret store, never from source code.
 */
export function createIncidentStore({ now = () => Date.now() } = {}) {
  const incidents = new Map();
  const crypto = new CryptoManager();
  const notesKey = randomBytes(32);
  const guard = new ThreatModelGuard({
    transitions: STATUS_TRANSITIONS,
    abuseRules: [
      {
        id: "too_many_open_incidents",
        message: `You already have ${MAX_OPEN_PER_REPORTER} open incidents. Resolve some before filing more.`,
        check: (ctx) => ctx.openByReporter < MAX_OPEN_PER_REPORTER
      }
    ]
  });
  let nextId = 1;

  const summary = ({ notes, ...incident }) => ({ ...incident, noteCount: notes.length });

  function get(id) {
    const incident = incidents.get(String(id));
    if (!incident) throw new SecurityError(SecurityErrorCode.INVALID_INPUT, "No such incident");
    return incident;
  }

  return {
    list() {
      return [...incidents.values()].map(summary).sort((a, b) => b.createdAt - a.createdAt);
    },

    get(id) {
      return summary(get(id));
    },

    create({ title, severity, description }, reporter) {
      const openByReporter = [...incidents.values()].filter((i) => i.reporterId === reporter.userId && i.status !== "closed").length;
      const abuse = guard.evaluateAbuseCase({ openByReporter });
      if (!abuse.valid) {
        throw new SecurityError(SecurityErrorCode.INVALID_INPUT, abuse.violations[0].message, { violations: abuse.violations });
      }
      const id = String(nextId++);
      const incident = {
        id,
        title,
        severity,
        description,
        status: "open",
        locked: false,
        reporterId: reporter.userId,
        reporterName: reporter.metadata.name,
        createdAt: now(),
        updatedAt: now(),
        notes: []
      };
      incidents.set(id, incident);
      return summary(incident);
    },

    transition(id, status) {
      const incident = get(id);
      const { valid } = guard.validateTransition(incident.status, status);
      if (!valid) {
        throw new SecurityError(SecurityErrorCode.INVALID_INPUT, `An incident can't move from ${incident.status} to ${status}`);
      }
      incident.status = status;
      incident.updatedAt = now();
      return summary(incident);
    },

    setLocked(id, locked) {
      const incident = get(id);
      incident.locked = locked;
      incident.updatedAt = now();
      return summary(incident);
    },

    remove(id) {
      get(id);
      incidents.delete(String(id));
    },

    addNote(id, text, author) {
      const incident = get(id);
      incident.notes.push({ authorName: author.metadata.name, createdAt: now(), payload: crypto.encrypt(text, notesKey) });
      return incident.notes.length;
    },

    readNotes(id) {
      return get(id).notes.map(({ authorName, createdAt, payload }) => ({
        authorName,
        createdAt,
        text: crypto.decrypt(payload, notesKey)
      }));
    },

    // For tests and the README: what is actually held in memory.
    rawNotes(id) {
      return get(id).notes.map((note) => note.payload);
    }
  };
}
