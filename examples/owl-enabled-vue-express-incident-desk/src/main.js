import { createApp } from "vue";
import { vSafeHtml } from "@owasp-webshield/vue";
import App from "./App.vue";
import { owl } from "./owl.js";
import { router } from "./router.js";
import "./style.css";

createApp(App)
  .use(owl)
  .use(router)
  // A03: renders incident descriptions; the app never uses v-html.
  .directive("safe-html", vSafeHtml)
  .mount("#app");
