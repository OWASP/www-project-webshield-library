import { createRouter, createWebHistory } from "vue-router";
import { installOwlRouterGuard } from "@owasp-webshield/vue";
import { incidentResource } from "../shared/policy.js";
import { owl } from "./owl.js";
import AdminView from "./views/AdminView.vue";
import ForbiddenView from "./views/ForbiddenView.vue";
import IncidentsView from "./views/IncidentsView.vue";
import IncidentView from "./views/IncidentView.vue";
import LoginView from "./views/LoginView.vue";
import NewIncidentView from "./views/NewIncidentView.vue";

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", redirect: "/incidents" },
    { path: "/login", component: LoginView },
    { path: "/403", component: ForbiddenView },
    { path: "/incidents", component: IncidentsView, meta: { permission: { action: "read", resource: "incidents" } } },
    { path: "/incidents/new", component: NewIncidentView, meta: { permission: { action: "create", resource: "incidents" } } },
    {
      path: "/incidents/:id",
      component: IncidentView,
      meta: { permission: { action: "read", resource: (to) => incidentResource(to.params.id) } }
    },
    { path: "/admin", component: AdminView, meta: { permission: { action: "view", resource: "audit" } } },
    { path: "/:pathMatch(.*)*", redirect: "/incidents" }
  ]
});

// A01/A07: checks every navigation, and leaves a protected page as soon as the
// session ends or expires (the API would refuse its data anyway).
installOwlRouterGuard(router, owl, { loginRoute: "/login", forbiddenRoute: "/403" });
