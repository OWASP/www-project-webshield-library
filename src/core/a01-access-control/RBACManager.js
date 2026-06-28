export class RBACManager {
  constructor() {
    this.roles = new Map();
  }

  defineRole(role, permissions = [], inherits = []) {
    this.roles.set(role, {
      permissions: new Set(permissions),
      inherits: new Set(inherits)
    });
  }

  _flattenPermissions(role, visited = new Set()) {
    if (visited.has(role)) return new Set();
    visited.add(role);
    const current = this.roles.get(role);
    if (!current) return new Set();

    const output = new Set(current.permissions);
    for (const parentRole of current.inherits) {
      for (const perm of this._flattenPermissions(parentRole, visited)) {
        output.add(perm);
      }
    }
    return output;
  }

  can(role, action, resource) {
    const key = `${action}:${resource}`;
    const wildcard = `${action}:*`;
    const perms = this._flattenPermissions(role);
    return perms.has(key) || perms.has(wildcard) || perms.has("*");
  }
}