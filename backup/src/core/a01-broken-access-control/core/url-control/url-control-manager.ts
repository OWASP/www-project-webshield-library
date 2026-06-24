import { parse as parsePath } from "path-to-regexp";
import {
  URLPattern,
  URLRequestContext,
  URLAccessResult,
  URLControlOptions,
  URLCondition,
  CustomConditionValidator,
  RoleConditionConfig,
  IPConditionConfig,
  TimeConditionConfig,
  RateConditionConfig,
  HeaderConditionConfig,
  QueryConditionConfig,
  CustomConditionConfig,
} from "./interfaces";
import { HttpMethod } from "./types";
import {
  URLControlError,
  InvalidPatternError,
  InvalidConditionError,
  ValidatorNotFoundError,
  PatternConflictError,
  InvalidContextError,
  RateLimitExceededError,
  MissingHeaderError,
  MissingQueryParamError,
  IPRestrictedError,
  TimeRestrictedError,
} from "./errors";

export class URLControlManager {
  private patterns: URLPattern[] = [];
  private customValidators: Map<string, CustomConditionValidator> = new Map();
  private options: Required<URLControlOptions>;
  private cache: Map<string, { result: URLAccessResult; timestamp: number }> =
    new Map();

  constructor(options: URLControlOptions = {}) {
    this.options = {
      caseSensitive: options.caseSensitive ?? false,
      defaultAllow: options.defaultAllow ?? false,
      validators: options.validators ?? {},
      cache: {
        enabled: options.cache?.enabled ?? true,
        maxSize: options.cache?.maxSize ?? 1000,
        ttl: options.cache?.ttl ?? 60000, // 1 minute default
      },
    };

    // Register custom validators
    for (const [name, validator] of Object.entries(this.options.validators)) {
      this.registerValidator(name, validator);
    }
  }

  /**
   * Add a new URL pattern to the control list
   */
  public addPattern(pattern: URLPattern): void {
    // Validate pattern
    this.validatePattern(pattern);

    // Check for conflicts
    for (const existing of this.patterns) {
      if (this.patternsConflict(existing, pattern)) {
        throw new PatternConflictError(existing.pattern, pattern.pattern);
      }
    }

    // Add pattern, sorted by priority
    this.patterns.push(pattern);
    this.patterns.sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0));

    // Clear cache as patterns have changed
    this.clearCache();
  }

  /**
   * Remove a URL pattern from the control list
   */
  public removePattern(pattern: string): void {
    const index = this.patterns.findIndex((p) => p.pattern === pattern);
    if (index !== -1) {
      this.patterns.splice(index, 1);
      this.clearCache();
    }
  }

  /**
   * Check if a URL request is allowed
   */
  public async checkAccess(
    context: URLRequestContext
  ): Promise<URLAccessResult> {
    const cacheKey = this.getCacheKey(context);

    if (this.options.cache.enabled) {
      const cached = this.getCachedResult(cacheKey);
      if (cached) return cached;
    }

    const result = await this.evaluateAccess(context);

    if (this.options.cache.enabled) {
      this.cacheResult(cacheKey, result);
    }

    return result;
  }

  /**
   * Register a custom condition validator
   */
  public registerValidator(
    name: string,
    validator: CustomConditionValidator
  ): void {
    this.customValidators.set(name, validator);
  }

  /**
   * Clear the access check cache
   */
  public clearCache(): void {
    this.cache.clear();
  }

  private validatePattern(pattern: URLPattern): void {
    if (!pattern.pattern) {
      throw new InvalidPatternError(pattern.pattern, "Pattern cannot be empty");
    }

    try {
      // Test if pattern can be parsed
      parsePath(pattern.pattern);
    } catch (error) {
      throw new InvalidPatternError(pattern.pattern, "Invalid pattern syntax");
    }

    if (pattern.methods !== "ALL" && !Array.isArray(pattern.methods)) {
      throw new InvalidPatternError(
        pattern.pattern,
        'Methods must be an array or "ALL"'
      );
    }

    if (pattern.regex) {
      try {
        if (typeof pattern.regex === "string") {
          new RegExp(pattern.regex);
        }
      } catch (error) {
        throw new InvalidPatternError(pattern.pattern, "Invalid regex pattern");
      }
    }
  }

  private patternsConflict(p1: URLPattern, p2: URLPattern): boolean {
    // Check for exact pattern matches
    if (p1.pattern === p2.pattern) {
      // Check for method overlap
      const methods1 = p1.methods === "ALL" ? ["*"] : p1.methods;
      const methods2 = p2.methods === "ALL" ? ["*"] : p2.methods;

      return methods1.some((m1) =>
        methods2.some((m2) => m1 === m2 || m1 === "*" || m2 === "*")
      );
    }

    // For now, no other conflict checks
    // Could add more sophisticated pattern overlap detection
    return false;
  }

  private async evaluateAccess(
    context: URLRequestContext
  ): Promise<URLAccessResult> {
    const { url, method } = context;

    for (const pattern of this.patterns) {
      if (this.matchesPattern(url, method as HttpMethod, pattern)) {
        const params = this.extractParams(url, pattern);

        if (pattern.conditions) {
          const failedConditions = await this.checkConditions(
            pattern.conditions,
            context
          );
          if (failedConditions.length > 0) {
            return {
              allowed: false,
              pattern,
              params,
              failedConditions,
              error:
                failedConditions[0]?.errorMessage ??
                "Access denied by conditions",
            };
          }
        }

        return {
          allowed: pattern.allow,
          pattern,
          params,
        };
      }
    }

    return {
      allowed: this.options.defaultAllow,
      error: "No matching pattern found",
    };
  }

  private matchesPattern(
    url: string,
    method: HttpMethod,
    pattern: URLPattern
  ): boolean {
    // Check method first
    if (pattern.methods !== "ALL") {
      if (
        !pattern.methods.includes(method as HttpMethod) &&
        !pattern.methods.includes("*")
      ) {
        return false;
      }
    }

    // Use regex if provided
    if (pattern.regex) {
      const regex =
        typeof pattern.regex === "string"
          ? new RegExp(pattern.regex)
          : pattern.regex;
      return regex.test(url);
    }

    // Convert glob pattern to regex and test
    const regex = this.globToRegex(pattern.pattern);
    return regex.test(url);
  }

  private globToRegex(pattern: string): RegExp {
    let regexStr = pattern
      .replace(/\*\*/g, ".*")
      .replace(/\*/g, "[^/]*")
      .replace(/\?/g, "[^/]")
      .replace(/{(\w+)}/g, "([^/]+)");

    if (!this.options.caseSensitive) {
      regexStr = `(?i)${regexStr}`;
    }

    return new RegExp(`^${regexStr}$`);
  }

  private extractParams(
    url: string,
    pattern: URLPattern
  ): Record<string, string> {
    const params: Record<string, string> = {};

    // Only extract if pattern has parameters defined
    if (pattern.params) {
      const matches = url.match(this.globToRegex(pattern.pattern));
      if (matches) {
        const paramNames = Array.from(pattern.pattern.matchAll(/{(\w+)}/g)).map(
          (m) => m[1]
        );
        paramNames.forEach((name, i) => {
          params[name] = matches[i + 1];
        });
      }
    }

    return params;
  }

  private async checkConditions(
    conditions: URLCondition[],
    context: URLRequestContext
  ): Promise<URLCondition[]> {
    const failed: URLCondition[] = [];

    for (const condition of conditions) {
      const isValid = await this.evaluateCondition(condition, context);
      if (!isValid) {
        failed.push(condition);
      }
    }

    return failed;
  }

  private async evaluateCondition(
    condition: URLCondition,
    context: URLRequestContext
  ): Promise<boolean> {
    try {
      switch (condition.type) {
        case "role":
          return this.checkRoleCondition(
            condition.config as RoleConditionConfig,
            context
          );
        case "ip":
          return this.checkIPCondition(
            condition.config as IPConditionConfig,
            context
          );
        case "time":
          return this.checkTimeCondition(
            condition.config as TimeConditionConfig,
            context
          );
        case "rate":
          return await this.checkRateCondition(
            condition.config as RateConditionConfig,
            context
          );
        case "header":
          return this.checkHeaderCondition(
            condition.config as HeaderConditionConfig,
            context
          );
        case "query":
          return this.checkQueryCondition(
            condition.config as QueryConditionConfig,
            context
          );
        case "custom":
          return await this.checkCustomCondition(
            condition.config as CustomConditionConfig,
            context
          );
        default:
          throw new InvalidConditionError(
            condition.type,
            "Unknown condition type"
          );
      }
    } catch (error) {
      if (error instanceof URLControlError) {
        throw error;
      }
      throw new InvalidConditionError(
        condition.type,
        error instanceof Error ? error.message : String(error)
      );
    }
  }

  private checkRoleCondition(
    config: RoleConditionConfig,
    context: URLRequestContext
  ): boolean {
    if (!context.user?.roles) {
      return false;
    }

    if (config.requireAll) {
      return config.roles.every((role) => context.user!.roles.includes(role));
    }

    return config.roles.some((role) => context.user!.roles.includes(role));
  }

  private checkIPCondition(
    config: IPConditionConfig,
    context: URLRequestContext
  ): boolean {
    if (!context.ip) {
      throw new InvalidContextError("IP address not provided in context");
    }

    if (config.deny?.includes(context.ip)) {
      throw new IPRestrictedError(context.ip);
    }

    if (config.allow?.length) {
      return config.allow.includes(context.ip);
    }

    return config.defaultAllow ?? true;
  }

  private checkTimeCondition(
    config: TimeConditionConfig,
    context: URLRequestContext
  ): boolean {
    const now = new Date();
    const timezone = config.timezone || "UTC";
    const timeStr = now.toLocaleTimeString("en-US", { timeZone: timezone });
    const day = now.getDay();

    if (config.days && !config.days.includes(day)) {
      throw new TimeRestrictedError("Access not allowed on this day");
    }

    if (config.start && config.end) {
      const currentTime = this.parseTime(timeStr);
      const startTime = this.parseTime(config.start);
      const endTime = this.parseTime(config.end);

      if (currentTime < startTime || currentTime > endTime) {
        throw new TimeRestrictedError(
          `Access only allowed between ${config.start} and ${config.end}`
        );
      }
    }

    return true;
  }

  private async checkRateCondition(
    config: RateConditionConfig,
    context: URLRequestContext
  ): Promise<boolean> {
    // Note: This is a simplified rate limiting implementation
    // In a real application, you'd want to use a distributed rate limiter

    const key = this.getRateLimitKey(config.by, context);
    const now = Date.now();

    // Get existing requests in the window
    const requests = await this.getRateLimitCount(key, config.window);

    if (requests >= config.limit) {
      throw new RateLimitExceededError(config.limit, config.window);
    }

    // Record this request
    await this.recordRateLimitRequest(key, now, config.window);

    return true;
  }

  private checkHeaderCondition(
    config: HeaderConditionConfig,
    context: URLRequestContext
  ): boolean {
    if (!context.headers) {
      throw new InvalidContextError("Headers not provided in context");
    }

    const missingHeaders: string[] = [];

    for (const [header, value] of Object.entries(config.headers)) {
      const headerValue = context.headers[header.toLowerCase()];

      if (!headerValue) {
        missingHeaders.push(header);
        if (!config.matchAll) break;
      } else if (value instanceof RegExp) {
        if (!value.test(headerValue)) {
          missingHeaders.push(header);
          if (!config.matchAll) break;
        }
      } else if (headerValue !== value) {
        missingHeaders.push(header);
        if (!config.matchAll) break;
      }
    }

    if (missingHeaders.length > 0) {
      throw new MissingHeaderError(missingHeaders);
    }

    return true;
  }

  private checkQueryCondition(
    config: QueryConditionConfig,
    context: URLRequestContext
  ): boolean {
    if (!context.query) {
      throw new InvalidContextError("Query parameters not provided in context");
    }

    const missingParams: string[] = [];

    for (const [param, value] of Object.entries(config.params)) {
      const paramValue = context.query[param];

      if (!paramValue) {
        missingParams.push(param);
        if (!config.matchAll) break;
      } else if (value instanceof RegExp) {
        if (!value.test(paramValue)) {
          missingParams.push(param);
          if (!config.matchAll) break;
        }
      } else if (paramValue !== value) {
        missingParams.push(param);
        if (!config.matchAll) break;
      }
    }

    if (missingParams.length > 0) {
      throw new MissingQueryParamError(missingParams);
    }

    return true;
  }

  private async checkCustomCondition(
    config: CustomConditionConfig,
    context: URLRequestContext
  ): Promise<boolean> {
    const validator = this.customValidators.get(config.validator);
    if (!validator) {
      throw new ValidatorNotFoundError(config.validator);
    }

    return validator(context, config);
  }

  private parseTime(timeStr: string): number {
    const [hours, minutes] = timeStr.split(":").map(Number);
    return hours * 60 + minutes;
  }

  private getRateLimitKey(by: string, context: URLRequestContext): string {
    switch (by) {
      case "ip":
        if (!context.ip) {
          throw new InvalidContextError(
            "IP address not provided for rate limiting"
          );
        }
        return `rate:${context.ip}`;
      case "user":
        if (!context.user?.id) {
          throw new InvalidContextError(
            "User ID not provided for rate limiting"
          );
        }
        return `rate:${context.user.id}`;
      default:
        return `rate:${by}:${context[by] ?? "default"}`;
    }
  }

  private async getRateLimitCount(
    key: string,
    window: number
  ): Promise<number> {
    // This would typically use Redis or similar in production
    // Here we use in-memory storage for demonstration
    const now = Date.now();
    let count = 0;

    for (const [, entry] of this.cache) {
      if (entry.timestamp > now - window * 1000) {
        count++;
      }
    }

    return count;
  }

  private async recordRateLimitRequest(
    key: string,
    timestamp: number,
    window: number
  ): Promise<void> {
    // This would typically use Redis or similar in production
    this.cache.set(key, {
      result: { allowed: true },
      timestamp,
    });

    // Clean up old entries
    for (const [key, entry] of this.cache) {
      if (entry.timestamp < timestamp - window * 1000) {
        this.cache.delete(key);
      }
    }
  }

  private getCacheKey(context: URLRequestContext): string {
    return JSON.stringify({
      url: context.url,
      method: context.method,
      ip: context.ip,
      userId: context.user?.id,
    });
  }

  private getCachedResult(key: string): URLAccessResult | undefined {
    const cached = this.cache.get(key);
    if (!cached) return undefined;

    if (!cached || Date.now() - cached.timestamp > this.options.cache.ttl!) {
      this.cache.delete(key);
      return undefined;
    }

    return cached.result;
  }

  private cacheResult(key: string, result: URLAccessResult): void {
    // Maintain cache size limit
    if (
      this.options.cache.maxSize &&
      this.cache.size >= this.options.cache.maxSize
    ) {
      // Remove oldest entry
      const oldest = Array.from(this.cache.entries()).sort(
        ([, a], [, b]) => a.timestamp - b.timestamp
      )[0];
      if (oldest) {
        this.cache.delete(oldest[0]);
      }
    }

    this.cache.set(key, {
      result,
      timestamp: Date.now(),
    });
  }
}
