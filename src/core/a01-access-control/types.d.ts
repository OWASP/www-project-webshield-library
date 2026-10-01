/**
 * @typedef {Object} PermissionCheckInput
 * @property {string} role
 * @property {string} action
 * @property {string} resource
 */
export const ACCESS_CONTROL_TYPES: {};
export type PermissionCheckInput = {
    role: string;
    action: string;
    resource: string;
};
