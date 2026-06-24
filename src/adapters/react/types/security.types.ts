export interface SecurityContextType {
  isSecure: boolean;
  csrfToken: string | null;
  reportViolation(violation: SecurityViolation): void;
}

export interface SecurityViolation {
  type: 'xss' | 'csrf' | 'injection' | 'auth' | 'access';
  message: string;
  context?: Record<string, unknown>;
  timestamp: Date;
}

export interface ValidationRule {
  validate: (value: string) => boolean;
  message: string;
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
}
