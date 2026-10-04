import { computed, defineComponent, toValue } from "vue";
import { PermissionChecker } from "@owasp-webshield/core";
import { useOwl } from "../owl.js";

/**
 * The provided `ACLManager`.
 */
export function useACL() {
  const { aclManager } = useOwl();
  if (!aclManager) throw new Error("useACL needs an aclManager: pass one (or a client) to createOwl()");
  return aclManager;
}

/**
 * Whether the current session may perform `action` on `resource`: allowed if
 * any of its roles grants it, and an ACL deny applies to every role (the same
 * rule as the React adapter's `usePermission`). Both arguments can be refs or
 * getters, e.g. `usePermission("read", () => \`report:${route.params.id}\`)`.
 *
 * Recomputes when the session or the arguments change. RBAC/ACL rules changed
 * at runtime (`aclManager.setPolicy()`) are picked up on the next change.
 *
 * @param {import("vue").MaybeRefOrGetter<string>} action
 * @param {import("vue").MaybeRefOrGetter<string>} resource
 * @returns {import("vue").ComputedRef<{allowed: boolean, reason: string}>}
 */
export function usePermission(action, resource) {
  const { rbacManager, aclManager, auth } = useOwl();
  const checker = rbacManager && aclManager ? new PermissionChecker({ rbacManager, aclManager }) : null;

  return computed(() => {
    const roles = Array.isArray(auth.session.value?.roles) ? auth.session.value.roles : [];
    const currentAction = toValue(action);
    const currentResource = toValue(resource);
    if (roles.length === 0 || !checker) return { allowed: false, reason: "no_role" };

    let result;
    for (const role of roles) {
      result = checker.check({ role, action: currentAction, resource: currentResource });
      if (result.allowed || result.reason === "acl_deny_override") break;
    }
    return { allowed: result.allowed, reason: result.reason };
  });
}

/**
 * Renders the default slot when the session has the permission, otherwise the
 * `fallback` slot. Only controls what the UI shows; the server must still
 * authorize every request.
 */
export const PermissionGate = defineComponent({
  name: "PermissionGate",
  props: {
    action: { type: String, required: true },
    resource: { type: String, required: true }
  },
  setup(props, { slots }) {
    const permission = usePermission(
      () => props.action,
      () => props.resource
    );
    return () => (permission.value.allowed ? slots.default?.() : slots.fallback?.()) ?? null;
  }
});
