"use client";

/**
 * Global navigation bar: CryptoShield branding, the Security Mode Switch,
 * and the current browser-generated identity (with key fingerprint).
 */

import { useState } from "react";
import { KeyRound, Loader2, Settings, ShieldHalf } from "lucide-react";
import SecurityModeToggle from "@/components/SecurityModeToggle";
import KeyManager from "@/components/keys/KeyManager";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useUserProfile } from "@/store/UserProfileContext";

export default function Navbar() {
  const { mode } = useSecurityMode();
  const { profile, status } = useUserProfile();
  const [keysOpen, setKeysOpen] = useState(false);

  const isSecure = mode === "secure";

  return (
    <header className="flex h-16 items-center justify-between border-b border-slate-800 bg-slate-900/80 px-4 backdrop-blur">
      {/* Brand */}
      <div className="flex items-center gap-3">
        <div
          className={[
            "flex h-9 w-9 items-center justify-center rounded-lg",
            isSecure ? "bg-emerald-600" : "bg-red-600",
          ].join(" ")}
        >
          <ShieldHalf className="h-5 w-5 text-white" />
        </div>
        <div className="leading-tight">
          <h1 className="text-lg font-bold tracking-tight">CryptoShield</h1>
          <p className="text-xs text-slate-400">Email Transport Security Lab · Phase 1</p>
        </div>
      </div>

      {/* Mode switch — deliberately prominent */}
      <div className="flex items-center gap-4">
        <span
          className={[
            "hidden rounded-full px-3 py-1 text-xs font-bold uppercase tracking-wider md:inline",
            isSecure
              ? "bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/40"
              : "bg-red-500/10 text-red-400 ring-1 ring-red-500/40",
          ].join(" ")}
        >
          {isSecure ? "E2E Protection On" : "Plaintext / Spoofable"}
        </span>

        {/* Key management (export / import / CRL) */}
        <button
          onClick={() => setKeysOpen(true)}
          title="Key management — export, import, CRL"
          className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-300 transition-colors hover:bg-slate-800 hover:text-slate-100"
        >
          <Settings className="h-3.5 w-3.5" />
          Keys
        </button>

        <SecurityModeToggle />

        {/* Identity + key status */}
        <div className="hidden items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-300 lg:flex">
          <KeyRound className="h-3.5 w-3.5 text-slate-500" />
          {status === "generating" && (
            <span className="flex items-center gap-1.5">
              <Loader2 className="h-3 w-3 animate-spin" /> Generating RSA keys…
            </span>
          )}
          {status === "error" && <span className="text-red-400">Key generation failed</span>}
          {status === "ready" && profile && (
            <span title={`SHA-256: ${profile.certificate.x509.fingerprintSha256}`}>
              {profile.email} · key{" "}
              {profile.certificate.x509.fingerprintSha256.slice(0, 8)}
            </span>
          )}
        </div>
      </div>

      {/* Key management modal (renders nothing while closed) */}
      <KeyManager open={keysOpen} onClose={() => setKeysOpen(false)} />
    </header>
  );
}
