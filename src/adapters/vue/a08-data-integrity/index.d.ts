/**
 * An `HTTPClient` with CSRF and auth token support; rebuilt when a ref/getter
 * `options` changes.
 *
 * The CSRF token must come from the server, which is the side that validates it:
 * - by default it is read from the `XSRF-TOKEN` cookie on every request
 *   (double-submit cookie pattern, the default of `@owasp-webshield/express`;
 *   set `csrfCookieName` for another name), or
 * - pass a `csrfManager` holding a server-issued token (`csrfManager.setToken(token)`).
 * Pass `csrfCookieName: null` and no `csrfManager` to send no CSRF header.
 *
 * @param {import("vue").MaybeRefOrGetter<{
 *   baseUrl?: string,
 *   tokenProvider?: (() => string | null) | null,
 *   fetchImpl?: typeof fetch,
 *   csrfManager?: CSRFTokenManager | null,
 *   csrfCookieName?: string | null,
 *   allowedOrigins?: string[],
 *   outboundRequestPolicy?: object
 * }>} [options]
 * @returns {import("vue").ComputedRef<HTTPClient>}
 */
export function useSecureHttpClient(options?: import("vue").MaybeRefOrGetter<{
    baseUrl?: string;
    tokenProvider?: (() => string | null) | null;
    fetchImpl?: typeof fetch;
    csrfManager?: CSRFTokenManager | null;
    csrfCookieName?: string | null;
    allowedOrigins?: string[];
    outboundRequestPolicy?: object;
}>): import("vue").ComputedRef<HTTPClient>;
/**
 * `fetch` init with request-side hardening. X-Frame-Options/nosniff are
 * response headers and must be set by the server.
 * @param {RequestInit} [init]
 */
export function withSecurityHeaders(init?: RequestInit): {
    headers: {
        [n: number]: [string, string];
        length: number;
        toString(): string;
        toLocaleString(): string;
        toLocaleString(locales: string | string[], options?: Intl.NumberFormatOptions & Intl.DateTimeFormatOptions): string;
        pop(): [string, string];
        push(...items: [string, string][]): number;
        concat(...items: ConcatArray<[string, string]>[]): [string, string][];
        concat(...items: ([string, string] | ConcatArray<[string, string]>)[]): [string, string][];
        join(separator?: string): string;
        reverse(): [string, string][];
        shift(): [string, string];
        slice(start?: number, end?: number): [string, string][];
        sort(compareFn?: (a: [string, string], b: [string, string]) => number): [string, string][];
        splice(start: number, deleteCount?: number): [string, string][];
        splice(start: number, deleteCount: number, ...items: [string, string][]): [string, string][];
        unshift(...items: [string, string][]): number;
        indexOf(searchElement: [string, string], fromIndex?: number): number;
        lastIndexOf(searchElement: [string, string], fromIndex?: number): number;
        every<S extends [string, string]>(predicate: (value: [string, string], index: number, array: [string, string][]) => value is S, thisArg?: any): this is S[];
        every(predicate: (value: [string, string], index: number, array: [string, string][]) => unknown, thisArg?: any): boolean;
        some(predicate: (value: [string, string], index: number, array: [string, string][]) => unknown, thisArg?: any): boolean;
        forEach(callbackfn: (value: [string, string], index: number, array: [string, string][]) => void, thisArg?: any): void;
        map<U>(callbackfn: (value: [string, string], index: number, array: [string, string][]) => U, thisArg?: any): U[];
        filter<S extends [string, string]>(predicate: (value: [string, string], index: number, array: [string, string][]) => value is S, thisArg?: any): S[];
        filter(predicate: (value: [string, string], index: number, array: [string, string][]) => unknown, thisArg?: any): [string, string][];
        reduce(callbackfn: (previousValue: [string, string], currentValue: [string, string], currentIndex: number, array: [string, string][]) => [string, string]): [string, string];
        reduce(callbackfn: (previousValue: [string, string], currentValue: [string, string], currentIndex: number, array: [string, string][]) => [string, string], initialValue: [string, string]): [string, string];
        reduce<U>(callbackfn: (previousValue: U, currentValue: [string, string], currentIndex: number, array: [string, string][]) => U, initialValue: U): U;
        reduceRight(callbackfn: (previousValue: [string, string], currentValue: [string, string], currentIndex: number, array: [string, string][]) => [string, string]): [string, string];
        reduceRight(callbackfn: (previousValue: [string, string], currentValue: [string, string], currentIndex: number, array: [string, string][]) => [string, string], initialValue: [string, string]): [string, string];
        reduceRight<U>(callbackfn: (previousValue: U, currentValue: [string, string], currentIndex: number, array: [string, string][]) => U, initialValue: U): U;
        find<S extends [string, string]>(predicate: (value: [string, string], index: number, obj: [string, string][]) => value is S, thisArg?: any): S;
        find(predicate: (value: [string, string], index: number, obj: [string, string][]) => unknown, thisArg?: any): [string, string];
        findIndex(predicate: (value: [string, string], index: number, obj: [string, string][]) => unknown, thisArg?: any): number;
        fill(value: [string, string], start?: number, end?: number): [string, string][];
        copyWithin(target: number, start: number, end?: number): [string, string][];
        entries(): ArrayIterator<[number, [string, string]]>;
        keys(): ArrayIterator<number>;
        values(): ArrayIterator<[string, string]>;
        includes(searchElement: [string, string], fromIndex?: number): boolean;
        flatMap<U, This = undefined>(callback: (this: This, value: [string, string], index: number, array: [string, string][]) => U | readonly U[], thisArg?: This): U[];
        flat<A, D extends number = 1>(this: A, depth?: D): FlatArray<A, D>[];
        at(index: number): [string, string];
        [Symbol.iterator](): ArrayIterator<[string, string]>;
        [Symbol.unscopables]: {
            [x: number]: boolean;
            length?: boolean;
            toString?: boolean;
            toLocaleString?: boolean;
            pop?: boolean;
            push?: boolean;
            concat?: boolean;
            join?: boolean;
            reverse?: boolean;
            shift?: boolean;
            slice?: boolean;
            sort?: boolean;
            splice?: boolean;
            unshift?: boolean;
            indexOf?: boolean;
            lastIndexOf?: boolean;
            every?: boolean;
            some?: boolean;
            forEach?: boolean;
            map?: boolean;
            filter?: boolean;
            reduce?: boolean;
            reduceRight?: boolean;
            find?: boolean;
            findIndex?: boolean;
            fill?: boolean;
            copyWithin?: boolean;
            entries?: boolean;
            keys?: boolean;
            values?: boolean;
            includes?: boolean;
            flatMap?: boolean;
            flat?: boolean;
            at?: boolean;
            [Symbol.iterator]?: boolean;
            readonly [Symbol.unscopables]?: boolean;
        };
    } | {
        [x: string]: string;
    } | {
        append(name: string, value: string): void;
        delete(name: string): void;
        get(name: string): string | null;
        getSetCookie(): string[];
        has(name: string): boolean;
        set(name: string, value: string): void;
        forEach(callbackfn: (value: string, key: string, parent: Headers) => void, thisArg?: any): void;
        entries(): HeadersIterator<[string, string]>;
        keys(): HeadersIterator<string>;
        values(): HeadersIterator<string>;
        [Symbol.iterator](): HeadersIterator<[string, string]>;
    };
    body?: BodyInit | null;
    cache?: RequestCache;
    credentials: string;
    integrity?: string;
    keepalive?: boolean;
    method?: string;
    mode?: RequestMode;
    priority?: RequestPriority;
    redirect?: RequestRedirect;
    referrer?: string;
    referrerPolicy: string;
    signal?: AbortSignal | null;
    window?: null;
};
import { CSRFTokenManager } from "@owasp-webshield/core";
import { HTTPClient } from "@owasp-webshield/core";
