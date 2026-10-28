/**
 * Only allow same-site relative redirect targets.
 *
 * `callbackUrl` arrives from the query string, so it is attacker-controllable.
 * Reject absolute URLs, protocol-relative URLs ("//evil.example") and
 * backslash tricks that some browsers normalize into "//".
 */
export function safeRelativePath(
  value: string | null | undefined,
  fallback = "/",
): string {
  if (typeof value !== "string" || value.length === 0) return fallback;
  if (!value.startsWith("/")) return fallback;
  if (value.startsWith("//")) return fallback;
  if (value.includes("\\")) return fallback;
  return value;
}
