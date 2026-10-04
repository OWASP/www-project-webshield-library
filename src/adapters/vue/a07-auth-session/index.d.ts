/**
 * Reactive auth state from the provided `AuthManager`. `session` and
 * `isAuthenticated` update on login, logout, token refresh and token expiry.
 * @returns {{
 *   authManager: object | null,
 *   session: Readonly<import("vue").Ref<{userId: string, roles: string[], metadata: object} | null>>,
 *   isAuthenticated: import("vue").ComputedRef<boolean>
 * }}
 */
export function useAuth(): {
    authManager: object | null;
    session: Readonly<import("vue").Ref<{
        userId: string;
        roles: string[];
        metadata: object;
    } | null>>;
    isAuthenticated: import("vue").ComputedRef<boolean>;
};
/**
 * The current access token, or null when signed out or expired.
 * @returns {Readonly<import("vue").Ref<string | null>>}
 */
export function useAuthToken(): Readonly<import("vue").Ref<string | null>>;
/**
 * Renders the default slot when signed in, otherwise the `fallback` slot.
 * Only controls what the UI shows; the server must still authenticate every request.
 */
export const AuthGate: import("vue").DefineComponent<{}, () => import("vue").VNode<import("vue").RendererNode, import("vue").RendererElement, {
    [key: string]: any;
}>[], {}, {}, {}, import("vue").ComponentOptionsMixin, import("vue").ComponentOptionsMixin, {}, string, import("vue").PublicProps, Readonly<{}> & Readonly<{}>, {}, {}, {}, {}, string, import("vue").ComponentProvideOptions, true, {}, any>;
