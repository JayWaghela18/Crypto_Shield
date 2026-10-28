"use client";

/**
 * The cyber mode switch in the command bar:
 *
 *   [ ⚠ UNSAFE ]  <->  [ 🔒 SECURE · E2EE ]
 *
 * Unsafe = plaintext transport, spoofable sender, unsanitized rendering.
 * Secure = Web Crypto end-to-end protection on every send and receive.
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
      className="relative flex items-center gap-0.5 rounded-full border border-slate-700/70 bg-slate-950/80 p-0.5 shadow-innerline"
    >
      <span
        aria-hidden
        className={[
          "absolute inset-y-0.5 w-[calc(50%-2px)] rounded-full transition-all duration-300 ease-out",
          isSecure
            ? "left-[calc(50%+1px)] bg-emerald-500/95 shadow-glow-green"
            : "left-0.5 bg-rose-600/95 shadow-glow-red",
        ].join(" ")}
      />

      <button
        role="tab"
        aria-selected={!isSecure}
        onClick={() => setMode("unsafe")}
        className={[
          "relative z-10 flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-black uppercase tracking-wider transition-colors sm:px-3",
          !isSecure ? "text-white" : "text-slate-500 hover:text-slate-300",
        ].join(" ")}
        title="Plaintext transport, spoofable sender, unsanitized rendering"
      >
        <ShieldAlert className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">Unsafe</span>
      </button>

      <button
        role="tab"
        aria-selected={isSecure}
        onClick={() => setMode("secure")}
        className={[
          "relative z-10 flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-black uppercase tracking-wider transition-colors sm:px-3",
          isSecure ? "text-white" : "text-slate-500 hover:text-slate-300",
        ].join(" ")}
        title="End-to-end encrypted and signed (Web Crypto)"
      >
        <ShieldCheck className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">Secure</span>
      </button>
    </div>
  );
}
