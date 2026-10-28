"use client";

/**
 * Security indicators for received messages:
 *
 *   GREEN  "VERIFIED RSA-PSS"    — signature valid AND sender key matches the
 *                                  directory registration
 *   RED    "TAMPERED AES"        — decryption or signature check failed
 *   RED    "INVALID SIGNATURE"   — key binding failed / unknown sender
 *   AMBER  "REVOKED CERTIFICATE" — mathematically valid but on the CRL
 *   SLATE  "UNVERIFIED"          — plaintext message (no crypto at all)
 */

import {
  BadgeCheck,
  Loader2,
  Lock,
  ShieldAlert,
  ShieldOff,
  ShieldQuestion,
} from "lucide-react";
import type { VerificationResult } from "@/lib/types";

interface Props {
  verification: VerificationResult | null;
  working: boolean;
}

function shortFp(fp?: string): string | null {
  if (!fp) return null;
  return `${fp.slice(0, 10)}…${fp.slice(-10)}`;
}

const shell = "flex items-start gap-2.5 rounded-xl border px-3.5 py-2.5";

export default function VerificationBanner({ verification, working }: Props) {
  if (working || !verification || verification.status === "pending") {
    return (
      <div className={`${shell} border-slate-700/70 bg-slate-900/60 text-slate-300`}>
        <Loader2 className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-cyan-300" />
        <div>
          <p className="font-mono text-[10px] font-bold uppercase tracking-wider text-slate-300">
            running verification pipeline
          </p>
          <p className="mt-0.5 font-mono text-[10px] text-slate-500">
            unwrap → AES-GCM decrypt → SHA-256 → RSA-PSS verify → CRL → sanitize
          </p>
        </div>
      </div>
    );
  }

  const fp = shortFp(verification.fingerprint);
  const expected = shortFp(verification.expectedFingerprint);

  switch (verification.status) {
    case "verified":
      return (
        <div className={`${shell} border-emerald-500/40 bg-emerald-500/[0.08] shadow-glow-green`}>
          <BadgeCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
          <div className="min-w-0">
            <p className="font-mono text-[10px] font-black uppercase tracking-[0.16em] text-emerald-300">
              ✔ verified rsa-pss signature
            </p>
            <p className="mt-0.5 text-[11px] leading-relaxed text-emerald-200/75">
              {verification.reason}
            </p>
            {fp && (
              <p className="mt-1 truncate font-mono text-[9.5px] text-emerald-300/50">
                signing key · {fp}
                {expected && expected !== fp ? ` · directory ${expected}` : " · matches directory"}
              </p>
            )}
          </div>
        </div>
      );

    case "revoked":
      return (
        <div className={`${shell} border-orange-500/50 bg-orange-500/10 shadow-glow-red`}>
          <ShieldOff className="mt-0.5 h-4 w-4 shrink-0 text-orange-400" />
          <div className="min-w-0">
            <p className="font-mono text-[10px] font-black uppercase tracking-[0.16em] text-orange-300">
              ⛔ revoked certificate — rejected
            </p>
            <p className="mt-0.5 text-[11px] leading-relaxed text-orange-200/75">
              {verification.reason}
            </p>
            <p className="mt-1 font-mono text-[9.5px] text-orange-300/50">
              {fp ? `signing key ${fp} · ` : ""}CRL overrides a mathematically valid signature
            </p>
          </div>
        </div>
      );

    case "spoofed-tampered":
      return (
        <div className={`${shell} border-rose-500/50 bg-rose-500/10 shadow-glow-red`}>
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
          <div className="min-w-0">
            <p className="font-mono text-[10px] font-black uppercase tracking-[0.16em] text-rose-300">
              ✖ tampering detected — aes-gcm auth failed
            </p>
            <p className="mt-0.5 text-[11px] leading-relaxed text-rose-200/75">
              {verification.reason}
            </p>
          </div>
        </div>
      );

    case "spoofed-unverified":
      return (
        <div className={`${shell} border-rose-500/50 bg-rose-500/10 shadow-glow-red`}>
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
          <div className="min-w-0">
            <p className="font-mono text-[10px] font-black uppercase tracking-[0.16em] text-rose-300">
              ✖ invalid signature warning — spoofed / unverified
            </p>
            <p className="mt-0.5 text-[11px] leading-relaxed text-rose-200/75">
              {verification.reason}
            </p>
            {fp && expected && (
              <p className="mt-1 font-mono text-[9.5px] text-rose-300/60">
                carried {fp} · registered {expected}
              </p>
            )}
          </div>
        </div>
      );

    case "plaintext":
    default:
      return (
        <div className={`${shell} border-amber-500/40 bg-amber-500/[0.07]`}>
          <ShieldQuestion className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          <div className="min-w-0">
            <p className="font-mono text-[10px] font-black uppercase tracking-[0.16em] text-amber-300">
              ⚠ unverified — not end-to-end encrypted
            </p>
            <p className="mt-0.5 text-[11px] leading-relaxed text-amber-200/70">
              {verification.reason}
            </p>
            <p className="mt-1 flex items-center gap-1 font-mono text-[9.5px] text-amber-300/50">
              <Lock className="h-2.5 w-2.5" /> switch to secure mode to send signed mail
            </p>
          </div>
        </div>
      );
  }
}
