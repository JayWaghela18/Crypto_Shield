/**
 * DOMPurify sanitization helper (client-side).
 *
 * Used on every received secure message BEFORE rendering (Phase 2, deliverable
 * 2c) and by the secure-mode renderer — defense in depth against Stored XSS
 * even if an attacker somehow produced a "verified" HTML body.
 *
 * Dynamic import keeps DOMPurify (requires `window`) out of the server bundle.
 */

let domPurifyPromise: Promise<typeof import("dompurify").default> | null = null;

function loadPurify(): Promise<typeof import("dompurify").default> {
  if (!domPurifyPromise) {
    domPurifyPromise = import("dompurify").then((m) => m.default);
  }
  return domPurifyPromise;
}

/**
 * Strip scripts/event handlers/JavaScript URLs from an HTML string.
 * Always run this on content that will be injected into the DOM in
 * secure mode.
 */
export async function sanitizeHtml(html: string): Promise<string> {
  const DOMPurify = await loadPurify();
  return DOMPurify.sanitize(html);
}
