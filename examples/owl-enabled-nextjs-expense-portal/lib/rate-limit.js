/**
 * A04/A07: a fixed-window counter per key (here: the client IP). In memory, so
 * per instance; with several instances use a shared store such as Redis.
 */
export function createRateLimiter({ limit, windowMs = 60_000, now = () => Date.now() }) {
  const windows = new Map();

  function current(key) {
    const window = windows.get(key);
    if (!window || window.resetAt <= now()) return { count: 0, resetAt: now() + windowMs };
    return window;
  }

  return {
    /** True while `key` is still under the limit. */
    allows(key) {
      return current(key).count < limit;
    },

    hit(key) {
      const window = current(key);
      window.count += 1;
      windows.set(key, window);
    }
  };
}

/**
 * The client address, for rate limiting. Route handlers don't see the socket:
 * Next.js puts its address in X-Forwarded-For, but only when the request has
 * no such header, so a client talking to `next start` directly can write any
 * value there. Only entries added by your own proxies can be trusted.
 *
 * `trustedHops` is how many proxies in front of the app append to the header
 * (1 for a single nginx with `proxy_add_x_forwarded_for`, a load balancer, or
 * Vercel). The client is the entry that many places from the right. With no
 * proxy in front, the value is client-chosen and per-IP limits can be dodged,
 * which is why the per-account lockout in users.js doesn't depend on it.
 */
export function clientIp(headers, { trustedHops = Number(process.env.OWL_TRUSTED_PROXY_HOPS ?? 1) } = {}) {
  const forwarded = headers.get("x-forwarded-for");
  if (!forwarded) return "unknown";
  const hops = forwarded.split(",").map((hop) => hop.trim()).filter(Boolean);
  return hops.at(-Math.max(1, trustedHops)) ?? hops[0] ?? "unknown";
}
