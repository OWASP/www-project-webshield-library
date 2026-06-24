/**
 * Represents a URL pattern for access control
 */
import { HttpMethod, ConditionType } from "./types";

export interface URLPattern {
  /**
   * The pattern to match against URLs.
   * Supports glob patterns and regex-like syntax:
   * - * matches any sequence of characters within a path segment
   * - ** matches across path segments
   * - ? matches a single character
   * - {param} matches and captures a path segment
   * Examples:
   * - /api/users/*
   * - /api/users/{id}/posts
   * - /api/users/comments
   */
  pattern: string;

  /**
   * HTTP methods the pattern applies to
   */
  methods: HttpMethod[] | "ALL";

  /**
   * Optional regular expression for more complex matching
   * If provided, this will be used instead of the glob pattern
   */
  regex?: RegExp | string;

  /**
   * Named parameters extracted from the URL
   * Maps parameter names to their patterns
   */
  params?: Record<string, string>;

  /**
   * Priority of the pattern (lower number = higher priority)
   * Used to resolve conflicts when multiple patterns match
   */
  priority?: number;

  /**
   * Whether this pattern explicitly allows or denies access
   * Default is false (deny)
   */
  allow: boolean;

  /**
   * Optional conditions that must be met for the rule to apply
   */
  conditions?: URLCondition[];

  /**
   * Metadata about the pattern for documentation/debugging
   */
  meta?: {
    description?: string;
    tags?: string[];
    createdAt?: Date;
    updatedAt?: Date;
  };
}

/**
 * Represents a condition that must be met for URL access
 */
export interface URLCondition {
  /**
   * Type of condition to check
   */
  type: ConditionType;

  /**
   * Configuration for the condition based on type
   */
  config: URLConditionConfig;

  /**
   * Custom error message when condition fails
   */
  errorMessage?: string;
}

/**
 * Discriminated union type for different condition configurations
 */
export type URLConditionConfig =
  | (RoleConditionConfig & { type: "role" })
  | (IPConditionConfig & { type: "ip" })
  | (TimeConditionConfig & { type: "time" })
  | (RateConditionConfig & { type: "rate" })
  | (HeaderConditionConfig & { type: "header" })
  | (QueryConditionConfig & { type: "query" })
  | (CustomConditionConfig & { type: "custom" });

/**
 * Configuration for role-based conditions
 */
export interface RoleConditionConfig {
  /**
   * Required roles (any of these)
   */
  roles: string[];

  /**
   * Whether to require all roles (AND) instead of any (OR)
   */
  requireAll?: boolean;
}

/**
 * Configuration for IP-based conditions
 */
export interface IPConditionConfig {
  /**
   * Allowed IP addresses or CIDR ranges
   */
  allow?: string[];

  /**
   * Denied IP addresses or CIDR ranges
   */
  deny?: string[];

  /**
   * Whether to allow or deny by default if no match
   */
  defaultAllow?: boolean;
}

/**
 * Configuration for time-based conditions
 */
export interface TimeConditionConfig {
  /**
   * Start time in HH:mm format
   */
  start?: string;

  /**
   * End time in HH:mm format
   */
  end?: string;

  /**
   * Days of week (0 = Sunday)
   */
  days?: number[];

  /**
   * Timezone for time checks
   */
  timezone?: string;
}

/**
 * Configuration for rate limiting conditions
 */
export interface RateConditionConfig {
  /**
   * Maximum requests allowed
   */
  limit: number;

  /**
   * Time window in seconds
   */
  window: number;

  /**
   * Key to rate limit by (ip, user, custom)
   */
  by: string;
}

/**
 * Configuration for header-based conditions
 */
export interface HeaderConditionConfig {
  /**
   * Required headers and their values
   */
  headers: Record<string, string | RegExp>;

  /**
   * Whether to match all headers
   */
  matchAll?: boolean;
}

/**
 * Configuration for query parameter conditions
 */
export interface QueryConditionConfig {
  /**
   * Required query parameters and their values
   */
  params: Record<string, string | RegExp>;

  /**
   * Whether to match all parameters
   */
  matchAll?: boolean;
}

/**
 * Configuration for custom conditions
 */
export interface CustomConditionConfig {
  /**
   * Name of the custom validator
   */
  validator: string;

  /**
   * Additional options for the validator
   */
  options?: Record<string, any>;
}

/**
 * Request context for URL access checks
 */
export interface URLRequestContext {
  /**
   * Full URL being accessed
   */
  url: string;

  /**
   * HTTP method
   */
  method: string;

  /**
   * Request headers
   */
  headers?: Record<string, string>;

  /**
   * Query parameters
   */
  query?: Record<string, string>;

  /**
   * Client IP address
   */
  ip?: string;

  /**
   * Authenticated user information
   */
  user?: {
    id: string;
    roles: string[];
    [key: string]: any;
  };

  /**
   * Additional context data
   */
  [key: string]: any;
}

/**
 * Result of a URL access check
 */
export interface URLAccessResult {
  /**
   * Whether access is allowed
   */
  allowed: boolean;

  /**
   * The pattern that determined the result
   */
  pattern?: URLPattern;

  /**
   * Parameters extracted from the URL
   */
  params?: Record<string, string>;

  /**
   * Failed conditions if access was denied
   */
  failedConditions?: URLCondition[];

  /**
   * Error message if access was denied
   */
  error?: string;
}

/**
 * Options for URL access control configuration
 */
export interface URLControlOptions {
  /**
   * Whether to use case-sensitive matching
   */
  caseSensitive?: boolean;

  /**
   * Default action when no pattern matches
   */
  defaultAllow?: boolean;

  /**
   * Custom condition validators
   */
  validators?: Record<string, CustomConditionValidator>;

  /**
   * Cache configuration
   */
  cache?: {
    enabled: boolean;
    maxSize?: number;
    ttl?: number;
  };
}

/**
 * Function type for custom condition validators
 */
export type CustomConditionValidator = (
  context: URLRequestContext,
  config: CustomConditionConfig
) => boolean | Promise<boolean>;
