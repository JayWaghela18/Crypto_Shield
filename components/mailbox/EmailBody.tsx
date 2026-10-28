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
 *   scripts/event handlers.
 */

import { useEffect, useState } from "react";
import { ShieldAlert, ShieldCheck, Sparkles } from "lucide-react";
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
    import("dompurify")
      .then(({ default: DOMPurify }) => {
        if (!cancelled) setSanitized(DOMPurify.sanitize(html));
      })
      .catch((cause) => console.error("[CryptoShield] DOMPurify failed:", cause));
    return () => {
      cancelled = true;
    };
  }, [html]);

  return <div className="mail-content" dangerouslySetInnerHTML={{ __html: sanitized }} />;
}

export default function EmailBody({ html, mode }: EmailBodyProps) {
  const isSecure = mode === "secure";

  return (
    <div
      className={[
        "overflow-hidden rounded-xl border bg-slate-950/50",
        isSecure ? "border-emerald-500/20" : "border-rose-500/30",
      ].join(" ")}
    >
      <div
        className={[
          "flex flex-wrap items-center gap-2 border-b px-3 py-2 text-[10px] font-bold uppercase tracking-wider",
          isSecure
            ? "border-emerald-500/20 bg-emerald-500/[0.07] text-emerald-300"
            : "border-rose-500/20 bg-rose-500/[0.07] text-rose-300",
        ].join(" ")}
      >
        {isSecure ? (
          <>
            <ShieldCheck className="h-3.5 w-3.5" />
            secure render · DOMPurify
            <span className="ml-auto flex items-center gap-1 text-emerald-400/60">
              <Sparkles className="h-2.5 w-2.5" /> scripts stripped
            </span>
          </>
        ) : (
          <>
            <ShieldAlert className="h-3.5 w-3.5" />
            unsafe render · raw HTML
            <span className="ml-auto text-rose-400/70">Stored XSS vector</span>
          </>
        )}
      </div>

      <div className="p-4">
        {isSecure ? (
          <SanitizedHtml html={html} />
        ) : (
          // ⚠ INTENTIONALLY UNSAFE — do not copy into production code.
          <div className="mail-content" dangerouslySetInnerHTML={{ __html: html }} />
        )}
      </div>
    </div>
  );
}
