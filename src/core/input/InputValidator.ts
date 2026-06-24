/**
 * InputValidator - Validates user input against security patterns
 * Checks for valid email, URL, passwords, credit cards, etc.
 */

import { ValidationResult, ValidationRule } from './types';

export class InputValidator {
  /**
   * Email regex pattern
   */
  private static readonly EMAIL_REGEX =
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  /**
   * URL regex pattern
   */
  private static readonly URL_REGEX =
    /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&//=]*)$/;

  /**
   * Password regex - at least 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special
   */
  private static readonly STRONG_PASSWORD_REGEX =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  /**
   * Credit card regex pattern
   */
  private static readonly CREDIT_CARD_REGEX =
    /^(\d{4}[\s-]?){3}\d{4}$/;

  /**
   * Phone number regex pattern (simple)
   */
  private static readonly PHONE_REGEX =
    /^[\d\s\-\+\(\)]{10,}$/;

  /**
   * Validate email address
   */
  static validateEmail(email: string): ValidationResult {
    const errors: string[] = [];

    if (!email) {
      errors.push('Email is required');
      return { isValid: false, errors };
    }

    if (email.length > 254) {
      errors.push('Email is too long (max 254 characters)');
    }

    if (!this.EMAIL_REGEX.test(email)) {
      errors.push('Email format is invalid');
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Validate URL
   */
  static validateURL(url: string): ValidationResult {
    const errors: string[] = [];

    if (!url) {
      errors.push('URL is required');
      return { isValid: false, errors };
    }

    if (url.length > 2000) {
      errors.push('URL is too long (max 2000 characters)');
    }

    if (!this.URL_REGEX.test(url)) {
      errors.push('URL format is invalid');
    }

    // Check for dangerous protocols
    if (
      url.toLowerCase().includes('javascript:') ||
      url.toLowerCase().includes('data:')
    ) {
      errors.push('URL contains dangerous protocol');
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Validate password strength
   */
  static validatePassword(password: string): ValidationResult {
    const errors: string[] = [];

    if (!password) {
      errors.push('Password is required');
      return { isValid: false, errors };
    }

    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }

    if (password.length > 128) {
      errors.push('Password is too long (max 128 characters)');
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one digit');
    }

    if (!/[@$!%*?&]/.test(password)) {
      errors.push('Password must contain at least one special character (@$!%*?&)');
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Validate credit card number using Luhn algorithm
   */
  static validateCreditCard(cardNumber: string): ValidationResult {
    const errors: string[] = [];
    const cleanedCard = cardNumber.replace(/[\s-]/g, '');

    if (!cleanedCard) {
      errors.push('Card number is required');
      return { isValid: false, errors };
    }

    if (!/^\d{13,19}$/.test(cleanedCard)) {
      errors.push('Card number must contain 13-19 digits');
    }

    if (!this.luhnCheck(cleanedCard)) {
      errors.push('Card number is invalid (failed Luhn check)');
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Validate phone number
   */
  static validatePhone(phone: string): ValidationResult {
    const errors: string[] = [];

    if (!phone) {
      errors.push('Phone number is required');
      return { isValid: false, errors };
    }

    if (!this.PHONE_REGEX.test(phone)) {
      errors.push('Phone number format is invalid');
    }

    const digitsOnly = phone.replace(/\D/g, '');
    if (digitsOnly.length < 10) {
      errors.push('Phone number must contain at least 10 digits');
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Validate text length
   */
  static validateLength(
    text: string,
    minLength: number = 1,
    maxLength: number = 1000
  ): ValidationResult {
    const errors: string[] = [];

    if (!text) {
      errors.push('Text is required');
      return { isValid: false, errors };
    }

    if (text.length < minLength) {
      errors.push(`Text must be at least ${minLength} characters long`);
    }

    if (text.length > maxLength) {
      errors.push(`Text must not exceed ${maxLength} characters`);
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Validate against regex pattern
   */
  static validatePattern(text: string, pattern: RegExp, message?: string): ValidationResult {
    const errors: string[] = [];

    if (!text) {
      errors.push('Input is required');
      return { isValid: false, errors };
    }

    if (!pattern.test(text)) {
      errors.push(message || 'Input does not match the required format');
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Validate against multiple rules
   */
  static validateWithRules(text: string, rules: ValidationRule[]): ValidationResult {
    const errors: string[] = [];

    for (const rule of rules) {
      if (!rule.validate(text)) {
        errors.push(rule.message);
      }
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Validate integer
   */
  static validateInteger(value: string, min?: number, max?: number): ValidationResult {
    const errors: string[] = [];

    if (!value) {
      errors.push('Value is required');
      return { isValid: false, errors };
    }

    if (!/^-?\d+$/.test(value)) {
      errors.push('Value must be an integer');
      return { isValid: false, errors };
    }

    const num = parseInt(value, 10);

    if (min !== undefined && num < min) {
      errors.push(`Value must be at least ${min}`);
    }

    if (max !== undefined && num > max) {
      errors.push(`Value must not exceed ${max}`);
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Validate float
   */
  static validateFloat(value: string, min?: number, max?: number): ValidationResult {
    const errors: string[] = [];

    if (!value) {
      errors.push('Value is required');
      return { isValid: false, errors };
    }

    if (!/^-?\d+\.?\d*$/.test(value)) {
      errors.push('Value must be a number');
      return { isValid: false, errors };
    }

    const num = parseFloat(value);

    if (min !== undefined && num < min) {
      errors.push(`Value must be at least ${min}`);
    }

    if (max !== undefined && num > max) {
      errors.push(`Value must not exceed ${max}`);
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Validate username (alphanumeric, underscore, hyphen only)
   */
  static validateUsername(username: string): ValidationResult {
    const errors: string[] = [];

    if (!username) {
      errors.push('Username is required');
      return { isValid: false, errors };
    }

    if (username.length < 3) {
      errors.push('Username must be at least 3 characters long');
    }

    if (username.length > 32) {
      errors.push('Username must not exceed 32 characters');
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      errors.push('Username can only contain letters, numbers, underscore, and hyphen');
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Luhn algorithm for credit card validation
   */
  private static luhnCheck(cardNumber: string): boolean {
    let sum = 0;
    let isEven = false;

    for (let i = cardNumber.length - 1; i >= 0; i--) {
      let digit = parseInt(cardNumber[i], 10);

      if (isEven) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }

      sum += digit;
      isEven = !isEven;
    }

    return sum % 10 === 0;
  }
}
