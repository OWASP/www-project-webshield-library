/**
 * OWASP Web Shield - Core Library
 * Framework-agnostic security library for JavaScript applications
 * 
 * Exports all core security modules:
 * - Authentication & Token Management
 * - Access Control (RBAC & ACL)
 * - Input Validation & Sanitization
 * - CSRF Protection
 * - HTTP Client with Interceptors
 * - Event Emitter
 * - Error Handling
 */

// Authentication
export { AuthManager, TokenManager } from './auth';
export type {
  AuthConfig,
  AuthToken,
  LoginRequest,
  LoginResponse,
  User,
  Role,
  StorageAdapter,
} from './auth';

// Access Control
export { RBACManager, ACLManager, PermissionChecker } from './access-control';
export type {
  ACLAction,
  ACLPermission,
  ACLResource,
  RBACRole,
  RBACUserRole,
} from './access-control';

// Input Protection
export { InputSanitizer, InputValidator } from './input';
export type { ValidationResult, ValidationRule, SanitizationOptions } from './input';

// CSRF Protection
export { CSRFTokenManager } from './csrf';
export type { CSRFToken, CSRFConfig } from './csrf';

// HTTP Client
export { HTTPClient } from './http';
export type {
  HTTPConfig,
  HTTPResponse,
  HTTPRequest,
  RequestInterceptor,
  ResponseInterceptor,
  ErrorInterceptor,
} from './http';

// Events
export { EventEmitter } from './events';
export type { EventListener } from './events';

// Error Handling
export { SecurityError, SecurityErrorCode, isSecurityError } from './error';

/**
 * Version
 */
export const VERSION = '0.1.0';

/**
 * Library info
 */
export const LIBRARY_INFO = {
  name: '@owasp/webshield',
  version: VERSION,
  description: 'Framework-agnostic OWASP security library for JavaScript applications',
};
