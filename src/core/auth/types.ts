/**
 * Authentication Types
 * Defines core authentication interfaces and types
 */

/**
 * User interface representing an authenticated user
 */
export interface User {
  id: string;
  email: string;
  username?: string;
  roles: Role[];
  permissions: string[];
  lastLogin?: Date;
  metadata?: Record<string, any>;
}

/**
 * Role interface for role-based access control
 */
export interface Role {
  id: string;
  name: string;
  permissions: string[];
  hierarchy?: number;
}

/**
 * AuthToken interface representing JWT or similar tokens
 */
export interface AuthToken {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number; // Duration in milliseconds
  type: 'Bearer' | 'Basic' | 'Custom';
  issuedAt: number; // Timestamp in milliseconds
}

/**
 * Authentication configuration
 */
export interface AuthConfig {
  apiBaseUrl: string;
  tokenRefreshThreshold?: number; // Milliseconds before expiry to trigger refresh
  storageAdapter?: StorageAdapter;
  onTokenExpired?: () => void;
  onTokenRefreshed?: () => void;
}

/**
 * Login request credentials
 */
export interface LoginRequest {
  email?: string;
  username?: string;
  password: string;
}

/**
 * Login response after successful authentication
 */
export interface LoginResponse {
  token: AuthToken;
  user: User;
}

/**
 * Storage adapter for storing tokens
 */
export interface StorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}
