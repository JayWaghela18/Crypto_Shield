"use client";

/**
 * The prominent Security Mode Switch in the navbar:
 *
 *   [ Unsafe Mode ]  <->  [ Secure Mode (CryptoShield) ]
 *
 * Unsafe = plaintext transport, spoofable sender, unsanitized rendering.
 * Secure = Web Crypto end-to-end protection (engine lands in Phase 2; the
 *          flag is already wired through every layer).
 */

import { ShieldAlert, ShieldCheck } from "lucide-react";
import { useSecurityMode } from "@/store/SecurityModeContext";

export default function SecurityModeToggle() {
  const { mode, setMode } = useSecurityMode();
  const isSecure = mode === "secure";

  return (
    <div
      role="tablist"
      aria-label="Security mode"
      className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 p-1"
    >
      {/* UNSAFE MODE */}
      <button
        role="tab"
        aria-selected={!isSecure}
        onClick={() => setMode("unsafe")}
        className={[
          "flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-semibold transition-colors",
          !isSecure
            ? "bg-red-600 text-white shadow-lg shadow-red-600/30"
            : "text-slate-400 hover:bg-slate-800 hover:text-slate-200",
        ].join(" ")}
        title="Plaintext transport, spoofable sender, unsanitized rendering"
      >
        <ShieldAlert className="h-4 w-4" />
        Unsafe Mode
      </button>

      {/* SECURE MODE */}
      <button
        role="tab"
        aria-selected={isSecure}
        onClick={() => setMode("secure")}
        className={[
          "flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-semibold transition-colors",
          isSecure
            ? "bg-emerald-600 text-white shadow-lg shadow-emerald-600/30"
            : "text-slate-400 hover:bg-slate-800 hover:text-slate-200",
        ].join(" ")}
        title="End-to-end encrypted and signed (Web Crypto)"
      >
        <ShieldCheck className="h-4 w-4" />
        Secure Mode (CryptoShield)
      </button>
    </div>
  );
}
