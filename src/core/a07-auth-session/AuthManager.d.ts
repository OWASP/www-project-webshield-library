export class AuthManager {
    /**
     * @param {{tokenManager: import('./TokenManager.js').TokenManager}} options
     */
    constructor(options: {
        tokenManager: import("./TokenManager.js").TokenManager;
    });
    tokenManager: import("./TokenManager.js").TokenManager;
    session: {
        userId: string;
        roles: any;
        metadata: any;
    };
    events: EventEmitter;
    setSession(session: any): void;
    clearSession(): void;
    getSession(): {
        userId: string;
        roles: any;
        metadata: any;
    };
    isAuthenticated(): boolean;
}
import { EventEmitter } from "../a09-logging-monitoring/EventEmitter.js";
