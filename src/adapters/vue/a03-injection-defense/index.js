import { computed, defineComponent, h, toValue } from "vue";
import { InputSanitizer } from "@owasp-webshield/core";

/**
 * An `InputSanitizer` for `profile`; rebuilt when a ref/getter argument changes.
 * @param {import("vue").MaybeRefOrGetter<"strict"|"moderate">} [profile]
 * @param {import("vue").MaybeRefOrGetter<{allowedClasses?: string[]}>} [options]
 * @returns {import("vue").ComputedRef<InputSanitizer>}
 */
export function useInputSanitizer(profile = "strict", options = {}) {
  return computed(() => new InputSanitizer(toValue(profile), { ...toValue(options) }));
}

/**
 * Renders `html` after sanitizing it. The sanitizer's output is HTML (entities
 * encoded, only allowlisted tags kept), so it is inserted as markup.
 */
export const SanitizedText = defineComponent({
  name: "SanitizedText",
  props: {
    html: { type: String, default: "" },
    profile: { type: String, default: "strict" },
    allowedClasses: { type: Array, default: undefined }
  },
  setup(props) {
    const sanitizer = useInputSanitizer(
      () => props.profile,
      () => ({ allowedClasses: props.allowedClasses })
    );
    return () => h("span", { innerHTML: sanitizer.value.sanitizeHTML(props.html) });
  }
});

// Sanitizers are stateless, so the directive shares one per configuration.
const sharedSanitizers = new Map();

function sanitizerFor(profile, allowedClasses) {
  const key = `${profile}|${(allowedClasses || []).join(" ")}`;
  if (!sharedSanitizers.has(key)) sharedSanitizers.set(key, new InputSanitizer(profile, { allowedClasses }));
  return sharedSanitizers.get(key);
}

function sanitizeBinding(binding) {
  const value = binding.value;
  if (value && typeof value === "object") {
    const { html = "", profile = binding.arg || "strict", allowedClasses } = value;
    return sanitizerFor(profile, allowedClasses).sanitizeHTML(String(html ?? ""));
  }
  return sanitizerFor(binding.arg || "strict").sanitizeHTML(value == null ? "" : String(value));
}

function render(el, binding) {
  const html = sanitizeBinding(binding);
  // Skip rewriting identical markup so focus and selection inside it survive re-renders.
  if (el.innerHTML !== html) el.innerHTML = html;
}

/**
 * Drop-in replacement for `v-html` that sanitizes first:
 *
 * - `v-safe-html="comment.body"`: strict profile (text only, entities encoded)
 * - `v-safe-html:moderate="post.body"`: keeps formatting tags and safe links/images
 * - `v-safe-html="{ html, profile, allowedClasses }"`
 *
 * Also works in server-side rendering. Register it as
 * `app.directive("safe-html", vSafeHtml)`, or import it into `<script setup>`
 * as `vSafeHtml`.
 */
export const vSafeHtml = {
  mounted: render,
  updated: render,
  getSSRProps(binding) {
    return { innerHTML: sanitizeBinding(binding) };
  }
};
