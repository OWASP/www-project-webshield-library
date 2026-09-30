export class TokenManager {
    /**
     * @param {{storageAdapter?: {getItem:(k:string)=>string|null,setItem:(k:string,v:string)=>void,removeItem:(k:string)=>void}, now?:()=>number, onRefresh?: (refreshToken:string, currentAccess:string|null)=>Promise<{accessToken:string, expiresAt:number, refreshToken?:string}>}} [options]
     */
    constructor(options?: {
        storageAdapter?: {
            getItem: (k: string) => string | null;
            setItem: (k: string, v: string) => void;
            removeItem: (k: string) => void;
        };
        now?: () => number;
        onRefresh?: (refreshToken: string, currentAccess: string | null) => Promise<{
            accessToken: string;
            expiresAt: number;
            refreshToken?: string;
        }>;
    });
    storage: {
        getItem: (k: string) => string | null;
        setItem: (k: string, v: string) => void;
        removeItem: (k: string) => void;
    } | {
        getItem: (key: any) => any;
        setItem: (key: any, value: any) => Map<any, any>;
        removeItem: (key: any) => boolean;
    };
    now: () => number;
    onRefresh: (refreshToken: string, currentAccess: string | null) => Promise<{
        accessToken: string;
        expiresAt: number;
        refreshToken?: string;
    }>;
    events: EventEmitter;
    key: string;
    _refreshing: Promise<string>;
    _generation: number;
    _read(): any;
    _write(tokens: any): void;
    setTokens(tokens: any): void;
    _store(tokens: any): void;
    clearTokens(): void;
    _endSession(): void;
    getTokens(): any;
    isAccessTokenExpired(): boolean;
    getAccessToken(): any;
    refreshIfNeeded(): Promise<any>;
    _refresh(tokens: any): Promise<string>;
}
import { EventEmitter } from "../a09-logging-monitoring/EventEmitter.js";
