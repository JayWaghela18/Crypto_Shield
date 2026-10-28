/**
 * Tiny in-memory rate limiter for authentication endpoints.
 *
 * This is a per-process guard, not a distributed one: it stops naive scripted
 * abuse on a single instance. A horizontally scaled deployment needs the same
 * policy at the edge or in a shared store (Redis/Upstash) — documented in
 * docs/SETUP_AND_RUN.md.
 */

interface Bucket {
  count: number;
  resetAt: number;
}

const state = globalThis as unknown as {
  __freeshieldRateLimits?: Map<string, Bucket>;
};

function buckets(): Map<string, Bucket> {
  if (!state.__freeshieldRateLimits) state.__freeshieldRateLimits = new Map();
  return state.__freeshieldRateLimits;
}

export interface RateLimitOutcome {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

/** Consume one token from `key`'s fixed window. */
export function consumeRateLimit(key: string, limit: number, windowMs: number): RateLimitOutcome {
  const now = Date.now();
  const store = buckets();

  // Opportunistic cleanup keeps the map bounded on long-lived instances.
  if (store.size > 5_000) {
    for (const [bucketKey, bucket] of store) {
      if (bucket.resetAt <= now) store.delete(bucketKey);
    }
  }

  const current = store.get(key);
  if (!current || current.resetAt <= now) {
    store.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: limit - 1, retryAfterSeconds: 0 };
  }

  if (current.count >= limit) {
    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.max(1, Math.ceil((current.resetAt - now) / 1000)),
    };
  }

  current.count += 1;
  return { allowed: true, remaining: limit - current.count, retryAfterSeconds: 0 };
}

/**
 * Best-effort client address. Only meaningful when a trusted proxy sets these
 * headers; otherwise every client collapses onto the same bucket.
 */
export function requestIp(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0]?.trim() || "unknown";
  return request.headers.get("x-real-ip")?.trim() || "unknown";
}
