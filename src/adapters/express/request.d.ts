// Adds the state the middleware attaches to the request to Express's `Request`
// type (@types/express declares it in the global `Express` namespace), so
// route handlers can read `req.owl.session` without a cast.

/** The session stored by `requireAuth()`. */
export interface OwlSession {
  userId: string;
  roles: string[];
  metadata: Record<string, any>;
}

/** Per-request OWL state on `req.owl`. */
export interface OwlRequestState {
  /** Set by `requireAuth()`. */
  session?: OwlSession;
  /** Set by `guardOutboundUrl()`: the validated URL. */
  outboundUrl?: URL;
}

declare global {
  namespace Express {
    interface Request {
      owl?: OwlRequestState;
    }
  }
}
