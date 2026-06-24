export interface PasswordValidationResult {
  isValid: boolean;
  feedback: string[];
}

export class Validators {
  static validateEmail(email: string): boolean {
    if (!email || typeof email !== 'string') return false;
    if (email.length > 254) return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  static validateURL(url: string): boolean {
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }

  static validatePassword(password: string): PasswordValidationResult {
    const feedback: string[] = [];
    if (password.length < 8)
      feedback.push('Password must be at least 8 characters');
    if (password.length > 128)
      feedback.push('Password must be at most 128 characters');
    if (!/[A-Z]/.test(password))
      feedback.push('Password must contain at least one uppercase letter');
    if (!/[a-z]/.test(password))
      feedback.push('Password must contain at least one lowercase letter');
    if (!/\d/.test(password))
      feedback.push('Password must contain at least one number');
    if (!/[@$!%*?&]/.test(password))
      feedback.push('Password must contain at least one special character (@$!%*?&)');
    return { isValid: feedback.length === 0, feedback };
  }

  /** Luhn-algorithm credit card validation */
  static validateCreditCard(cardNumber: string): boolean {
    const digits = cardNumber.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let isEven = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = parseInt(digits[i], 10);
      if (isEven) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      isEven = !isEven;
    }
    return sum % 10 === 0;
  }

  static validatePhone(phone: string): boolean {
    return /^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/.test(
      phone
    );
  }

  static validateLength(
    input: string,
    min: number,
    max: number
  ): boolean {
    return input.length >= min && input.length <= max;
  }

  static validateUsername(username: string): boolean {
    return /^[a-zA-Z0-9_-]{3,32}$/.test(username);
  }
}
