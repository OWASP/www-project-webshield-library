import { defineComponent, h } from "vue";
import { useOwl } from "../owl.js";

/**
 * The provided `SecurityLogger` and `EventEmitter` (either can be null).
 * @returns {{logger: object | null, events: object | null}}
 */
export function useSecurityMonitoring() {
  const { logger, events } = useOwl();
  return { logger, events };
}

/**
 * An accessible alert. Content comes from `message` or the default slot, and
 * is rendered as text, never as HTML.
 */
export const SecurityAlert = defineComponent({
  name: "SecurityAlert",
  props: {
    message: { type: String, default: "" },
    level: { type: String, default: "warn" }
  },
  setup(props, { slots }) {
    return () => h("div", { role: "alert", "data-level": props.level }, slots.default ? slots.default() : props.message);
  }
});
