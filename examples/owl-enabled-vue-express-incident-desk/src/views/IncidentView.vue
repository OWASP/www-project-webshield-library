<script setup>
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { PermissionGate, SecurityAlert, usePermission } from "@owasp-webshield/vue";
import { incidentResource, STATUS_LABELS, STATUS_TRANSITIONS } from "../../shared/policy.js";
import { useApi } from "../api.js";

const api = useApi();
const route = useRoute();
const router = useRouter();
const incident = ref(null);
const notes = ref([]);
const noteText = ref("");
const error = ref("");

const resource = computed(() => incidentResource(route.params.id));
const canReadNotes = usePermission("note", resource);
const nextStatuses = computed(() => (incident.value ? STATUS_TRANSITIONS[incident.value.status] : []));

async function run(action) {
  error.value = "";
  try {
    await action();
  } catch (caught) {
    error.value = caught.message;
  }
}

async function loadNotes() {
  if (canReadNotes.value.allowed && !incident.value?.locked) notes.value = await api.get(`/incidents/${route.params.id}/notes`);
}

onMounted(() =>
  run(async () => {
    incident.value = await api.get(`/incidents/${route.params.id}`);
    await loadNotes();
  })
);

const moveTo = (status) =>
  run(async () => {
    incident.value = await api.patch(`/incidents/${route.params.id}/status`, { status });
  });

const addNote = () =>
  run(async () => {
    await api.post(`/incidents/${route.params.id}/notes`, { text: noteText.value });
    noteText.value = "";
    await loadNotes();
  });

const setLocked = (locked) =>
  run(async () => {
    incident.value = await api.put(`/incidents/${route.params.id}/lock`, { locked });
    if (!locked) await loadNotes();
  });

const remove = () =>
  run(async () => {
    await api.del(`/incidents/${route.params.id}`);
    await router.push("/incidents");
  });
</script>

<template>
  <section v-if="incident" class="card">
    <div class="row">
      <h1 id="page-title">{{ incident.title }}</h1>
      <span :class="['badge', incident.severity]">{{ incident.severity }}</span>
    </div>
    <p class="muted">
      <span id="status">{{ STATUS_LABELS[incident.status] }}</span> · reported by {{ incident.reporterName }}
      <span v-if="incident.locked" id="locked-flag"> · 🔒 locked by an admin</span>
    </p>

    <!-- A03: stored HTML is sanitized by the API and again here before rendering. -->
    <div id="description" class="description" v-safe-html:moderate="incident.description"></div>

    <SecurityAlert v-if="error" id="action-error" :message="error" level="error" />

    <PermissionGate action="update" :resource="resource">
      <div class="actions" id="status-actions">
        <span class="label">Move to</span>
        <button
          v-for="status in nextStatuses"
          :key="status"
          :id="`move-${status}`"
          :disabled="incident.locked"
          @click="moveTo(status)"
        >
          {{ STATUS_LABELS[status] }}
        </button>
        <span v-if="!nextStatuses.length" class="muted">Closed incidents are final.</span>
      </div>
    </PermissionGate>

    <PermissionGate action="note" :resource="resource">
      <section class="notes" id="notes">
        <h2>Private notes <small class="muted">(responders only, encrypted at rest)</small></h2>
        <ul>
          <li v-for="(note, index) in notes" :key="index">
            <strong>{{ note.authorName }}</strong>: {{ note.text }}
          </li>
        </ul>
        <form v-if="!incident.locked" @submit.prevent="addNote" class="inline">
          <input id="note-text" v-model="noteText" placeholder="Add a private note" maxlength="2000" required />
          <button id="add-note" type="submit">Add note</button>
        </form>
      </section>
      <template #fallback>
        <p class="muted" id="notes-hidden">Private notes are visible to responders.</p>
      </template>
    </PermissionGate>

    <div class="actions danger-zone">
      <PermissionGate action="lock" :resource="resource">
        <button id="toggle-lock" class="secondary" @click="setLocked(!incident.locked)">
          {{ incident.locked ? "Unlock" : "Lock" }} incident
        </button>
      </PermissionGate>
      <PermissionGate action="delete" :resource="resource">
        <button id="delete" class="danger" @click="remove">Delete</button>
      </PermissionGate>
    </div>
  </section>
  <SecurityAlert v-else-if="error" id="load-error" :message="error" level="error" />
</template>
