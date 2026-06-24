/**
 * Common types used across access control interfaces
 */

export type Principal = {
  id: string;
  roles?: string[];
  permissions?: string[];
  attributes?: Record<string, any>;
};

export type Resource = {
  type: string;
  id: string;
  attributes?: Record<string, any>;
};

export type Permission = {
  action: string;
  resource: string;
  conditions?: Record<string, any>;
};

export type AccessRequest = {
  principal: Principal;
  action: string;
  resource: Resource;
  context?: Record<string, any>;
};

export type AccessResponse = {
  allowed: boolean;
  reason?: string;
  metadata?: Record<string, any>;
};

export type URLPattern = {
  pattern: string;
  method?: string | string[];
  matchQuery?: boolean;
  caseSensitive?: boolean;
};

export type SecurityContext = {
  principal?: Principal;
  session?: {
    id: string;
    expiresAt?: number;
    [key: string]: any;
  };
  metadata?: Record<string, any>;
};
