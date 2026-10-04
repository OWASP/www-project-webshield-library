<script setup>
import { onMounted, ref } from "vue";
import { PermissionGate, SecurityAlert } from "@owasp-webshield/vue";
import { STATUS_LABELS } from "../../shared/policy.js";
import { useApi } from "../api.js";

const api = useApi();
const incidents = ref([]);
const error = ref("");
const loaded = ref(false);

onMounted(async () => {
  try {
    incidents.value = await api.get("/incidents");
  } catch (caught) {
    error.value = caught.message;
  } finally {
    loaded.value = true;
  }
});
</script>

<template>
  <section>
    <div class="row">
      <h1 id="page-title">Incidents</h1>
      <PermissionGate action="create" resource="incidents">
        <RouterLink to="/incidents/new" class="button">Report incident</RouterLink>
      </PermissionGate>
    </div>
    <SecurityAlert v-if="error" :message="error" level="error" />
    <p v-else-if="loaded && !incidents.length" class="muted" id="empty">No incidents yet.</p>
    <table v-else-if="incidents.length" id="incident-list">
      <thead>
        <tr><th>Title</th><th>Severity</th><th>Status</th><th>Reporter</th><th></th></tr>
      </thead>
      <tbody>
        <tr v-for="incident in incidents" :key="incident.id">
          <!-- Interpolation is always text: a title can't inject markup. -->
          <td><RouterLink :to="`/incidents/${incident.id}`">{{ incident.title }}</RouterLink></td>
          <td><span :class="['badge', incident.severity]">{{ incident.severity }}</span></td>
          <td>{{ STATUS_LABELS[incident.status] }}</td>
          <td>{{ incident.reporterName }}</td>
          <td><span v-if="incident.locked" title="Locked by an admin">🔒</span></td>
        </tr>
      </tbody>
    </table>
  </section>
</template>
