/**
 * Origin check for state-changing requests.
 *
 * Session cookies are SameSite=Lax, which blocks cross-site POSTs in modern
 * browsers, but login CSRF and proxy misconfiguration are cheap to defend
 * against: require the browser's `Origin` header to match this deployment.
 */

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Allowed browser origins: the request origin plus an explicitly configured app URL. */
export function allowedOrigins(request: Request): string[] {
  const origins = new Set<string>();
  try {
    origins.add(new URL(request.url).origin);
  } catch {
    // A malformed request URL is handled by the false return below.
  }
  for (const configured of [process.env.NEXT_PUBLIC_APP_URL, process.env.APP_ORIGIN]) {
    if (!configured) continue;
    try {
      origins.add(new URL(configured).origin);
    } catch {
      // Ignore an invalid env value rather than failing every request.
    }
  }
  return [...origins];
}

/**
 * True when a request is a safe method or carries an `Origin` header matching
 * an allowed origin. Requests without `Origin` are rejected for mutations:
 * browsers always send it on cross-origin and same-origin POSTs.
 */
export function isSameOriginRequest(request: Request): boolean {
  if (SAFE_METHODS.has(request.method.toUpperCase())) return true;
  const origin = request.headers.get("origin");
  if (!origin) return false;
  return allowedOrigins(request).includes(origin);
}
