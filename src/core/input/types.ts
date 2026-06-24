/**
 * Input Validation Types
 */

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
}

export interface ValidationRule {
  validate: (value: string) => boolean;
  message: string;
}

export interface SanitizationOptions {
  allowedTags?: string[];
  allowedAttributes?: Record<string, string[]>;
  stripScripts?: boolean;
  normalizeWhitespace?: boolean;
  encodeHTML?: boolean;
}

export interface CSRFConfig {
  headerName?: string;
  cookieName?: string;
  tokenLength?: number;
  tokenExpiryMs?: number;
}
