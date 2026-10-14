"use client";

/**
 * Security indicators for received messages (Phase 2, deliverable 3):
 *
 *   GREEN  "VERIFIED SIGNATURE"        — signature valid AND sender key
 *                                        matches the directory registration
 *   RED    "SPOOFED / TAMPERED"        — decryption or signature check failed
 *   RED    "SPOOFED / UNVERIFIED"      — key binding failed / unknown sender
 *   AMBER  "UNVERIFIED"                — Phase-1 plaintext (no crypto at all)
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

/** Shorten a fingerprint for display: A1B2C3…F9E8 */
function shortFp(fp?: string): string | null {
  if (!fp) return null;
  return `${fp.slice(0, 8)}…${fp.slice(-8)}`;
}

export default function VerificationBanner({ verification, working }: Props) {
  if (working || !verification || verification.status === "pending") {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-800/60 px-4 py-2.5 text-sm text-slate-300">
        <Loader2 className="h-4 w-4 animate-spin" />
        Running cryptographic verification (unwrap → decrypt → hash → verify)…
      </div>
    );
  }

  const fp = shortFp(verification.fingerprint);
  const expected = shortFp(verification.expectedFingerprint);

  switch (verification.status) {
    case "verified":
      return (
        <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-3">
          <p className="flex items-center gap-2 text-sm font-bold text-emerald-400">
            <BadgeCheck className="h-4 w-4" />
            ✔ VERIFIED SIGNATURE
          </p>
          <p className="mt-1 text-xs text-emerald-300/80">{verification.reason}</p>
          {fp && (
            <p className="mt-1 font-mono text-[11px] text-emerald-300/60">
              signing key fingerprint {fp}
              {expected && expected !== fp ? ` (expected ${expected})` : ""}
            </p>
          )}
        </div>
      );

    case "revoked":
      return (
        <div className="rounded-lg border border-red-500/50 bg-red-500/10 px-4 py-3">
          <p className="flex items-center gap-2 text-sm font-bold text-red-400">
            <ShieldOff className="h-4 w-4" />
            ⛔ CERTIFICATE REVOKED — VALID SIGNATURE, REJECTED MESSAGE
          </p>
          <p className="mt-1 text-xs text-red-300/80">{verification.reason}</p>
          <p className="mt-1 font-mono text-[11px] text-red-300/60">
            {fp ? `signing key fingerprint ${fp} · ` : ""}CRL check overrides a mathematically
            valid signature
          </p>
        </div>
      );

    case "spoofed-tampered":
      return (
        <div className="rounded-lg border border-red-500/50 bg-red-500/10 px-4 py-3">
          <p className="flex items-center gap-2 text-sm font-bold text-red-400">
            <ShieldAlert className="h-4 w-4" />
            ✖ TAMPERING DETECTED — SPOOFED / TAMPERED
          </p>
          <p className="mt-1 text-xs text-red-300/80">{verification.reason}</p>
        </div>
      );

    case "spoofed-unverified":
      return (
        <div className="rounded-lg border border-red-500/50 bg-red-500/10 px-4 py-3">
          <p className="flex items-center gap-2 text-sm font-bold text-red-400">
            <ShieldAlert className="h-4 w-4" />
            ✖ INVALID SIGNATURE WARNING — SPOOFED / UNVERIFIED
          </p>
          <p className="mt-1 text-xs text-red-300/80">{verification.reason}</p>
          {fp && expected && (
            <p className="mt-1 font-mono text-[11px] text-red-300/60">
              used {fp} — registered {expected}
            </p>
          )}
        </div>
      );

    case "plaintext":
    default:
      return (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3">
          <p className="flex items-center gap-2 text-sm font-bold text-amber-400">
            <ShieldQuestion className="h-4 w-4" />
            ⚠ UNVERIFIED — not end-to-end encrypted
          </p>
          <p className="mt-1 text-xs text-amber-300/80">{verification.reason}</p>
          <p className="mt-1 flex items-center gap-1 text-[11px] text-amber-300/60">
            <Lock className="h-3 w-3" /> flip to Secure Mode to send verified mail
          </p>
        </div>
      );
  }
}
