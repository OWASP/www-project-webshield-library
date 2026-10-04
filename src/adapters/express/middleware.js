/**
 * Wraps an async step as `(req, res, next)` middleware. Express 4 doesn't catch
 * rejected promises, so a failing check would hang the request instead of
 * reaching the error handler; errors are forwarded to `next(err)` here instead.
 * `next()` is called outside the try so an error thrown further down the chain
 * isn't reported as this step's failure.
 */
export function middleware(step) {
  return function owlMiddleware(req, res, next) {
    Promise.resolve()
      .then(() => step(req, res))
      .then(() => next(), next);
  };
}

/**
 * Per-request OWL state (`req.owl.session`, `req.owl.outboundUrl`), kept under
 * one key so it can't collide with other middleware's `req.user`/`req.session`.
 */
export function owlState(req) {
  if (!req.owl) req.owl = {};
  return req.owl;
}
