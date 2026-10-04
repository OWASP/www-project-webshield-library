import { defineComponent } from "vue";
import { useOwl } from "../owl.js";

/**
 * Reactive auth state from the provided `AuthManager`. `session` and
 * `isAuthenticated` update on login, logout, token refresh and token expiry.
 * @returns {{
 *   authManager: object | null,
 *   session: Readonly<import("vue").Ref<{userId: string, roles: string[], metadata: object} | null>>,
 *   isAuthenticated: import("vue").ComputedRef<boolean>
 * }}
 */
export function useAuth() {
  const { authManager, auth } = useOwl();
  return { authManager, session: auth.session, isAuthenticated: auth.isAuthenticated };
}

/**
 * The current access token, or null when signed out or expired.
 * @returns {Readonly<import("vue").Ref<string | null>>}
 */
export function useAuthToken() {
  return useOwl().auth.accessToken;
}

/**
 * Renders the default slot when signed in, otherwise the `fallback` slot.
 * Only controls what the UI shows; the server must still authenticate every request.
 */
export const AuthGate = defineComponent({
  name: "AuthGate",
  setup(_props, { slots }) {
    const { isAuthenticated } = useAuth();
    return () => (isAuthenticated.value ? slots.default?.() : slots.fallback?.()) ?? null;
  }
});
