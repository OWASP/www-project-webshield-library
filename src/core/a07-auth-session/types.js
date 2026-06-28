/**
 * @typedef {Object} TokenPayload
 * @property {string} accessToken
 * @property {string | null} [refreshToken]
 * @property {number} expiresAt
 */

/**
 * @typedef {Object} AuthSession
 * @property {string} userId
 * @property {string[]} roles
 * @property {Record<string, unknown>} [metadata]
 */

export const AUTH_TYPES = {};