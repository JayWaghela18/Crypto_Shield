"use client";

/**
 * Email body renderer — the heart of the dual-mode rendering behavior.
 *
 * ⚠ UNSAFE MODE (intentional vulnerability demo):
 *   The HTML body is injected RAW with `dangerouslySetInnerHTML` — no
 *   sanitization at all. Any script markup stored by the server executes in
 *   the reader's session (Stored XSS). This is deliberately insecure and
 *   exists only to demonstrate the attack in a controlled local lab.
 *
 * SECURE MODE:
 *   The same body is passed through DOMPurify before rendering, stripping
 *   scripts/event handlers — the baseline HTML hygiene that accompanies the
 *   cryptographic transport (which arrives in Phase 2).
 */

import { useEffect, useState } from "react";
import { AlertTriangle, ShieldCheck } from "lucide-react";
import type { SecurityMode } from "@/lib/types";

interface EmailBodyProps {
  html: string;
  mode: SecurityMode;
}

/** Sanitized renderer (secure mode) — DOMPurify runs client-side only. */
function SanitizedHtml({ html }: { html: string }) {
  const [sanitized, setSanitized] = useState("");

  useEffect(() => {
    let cancelled = false;
    // Dynamic import keeps DOMPurify (needs `window`) out of the server bundle.
    import("dompurify")
      .then(({ default: DOMPurify }) => {
        if (!cancelled) setSanitized(DOMPurify.sanitize(html));
      })
      .catch((cause) => console.error("[CryptoShield] DOMPurify failed:", cause));
    return () => {
      cancelled = true;
    };
  }, [html]);

  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}

export default function EmailBody({ html, mode }: EmailBodyProps) {
  const isSecure = mode === "secure";

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60">
      {/* Renderer status banner */}
      <div
        className={[
          "flex items-center gap-2 border-b px-4 py-2 text-xs font-semibold",
          isSecure
            ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
            : "border-red-500/20 bg-red-500/10 text-red-400",
        ].join(" ")}
      >
        {isSecure ? (
          <>
            <ShieldCheck className="h-3.5 w-3.5" />
            SECURE RENDER — sanitized with DOMPurify
          </>
        ) : (
          <>
            <AlertTriangle className="h-3.5 w-3.5" />
            UNSAFE RENDER — raw HTML, NO sanitization (Stored XSS vector)
          </>
        )}
      </div>

      <div className="p-4 text-sm leading-relaxed text-slate-200">
        {isSecure ? (
          <SanitizedHtml html={html} />
        ) : (
          // ⚠ INTENTIONALLY UNSAFE — do not copy into production code.
          <div dangerouslySetInnerHTML={{ __html: html }} />
        )}
      </div>
    </div>
  );
}
