/**
 * @typedef {Object} CSRFTokenStorage
 * @property {() => string | null} get
 * @property {(token: string) => void} set
 */
export const DATA_INTEGRITY_TYPES: {};
export type CSRFTokenStorage = {
    get: () => string | null;
    set: (token: string) => void;
};
