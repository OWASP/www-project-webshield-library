export class SecurityLogger {
    /**
     * @param {{sink?: (entry: object) => void, redactKeys?: string[], valuePatterns?: RegExp[]}} [options]
     */
    constructor(options?: {
        sink?: (entry: object) => void;
        redactKeys?: string[];
        valuePatterns?: RegExp[];
    });
    sink: (entry: object) => void;
    redactKeys: string[];
    valuePatterns: RegExp[];
    _looksSensitive(value: any): boolean;
    redact(value: any, seen?: WeakSet<object>, depth?: number): any;
    log(level: any, event: any, details?: {}): void;
    info(event: any, details?: {}): void;
    warn(event: any, details?: {}): void;
    error(event: any, details?: {}): void;
}
