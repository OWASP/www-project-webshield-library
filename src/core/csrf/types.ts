/**
 * CSRF Types
 */

export interface CSRFToken {
  token: string;
  createdAt: number;
  expiresAt: number;
}

export interface CSRFConfig {
  headerName?: string;
  cookieName?: string;
  tokenLength?: number;
  tokenExpiryMs?: number;
}
