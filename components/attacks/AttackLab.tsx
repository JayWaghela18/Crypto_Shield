"use client";

/**
 * ⚔ Attack Lab (Phase 3) — explicit, user-triggered attack simulations.
 *
 * Every button runs the SAME attack in whichever security mode is active, so
 * the pair of outcomes teaches the contrast:
 *
 *   UNSAFE  → attack succeeds silently (accepted / reads normally / executes)
 *   SECURE  → the crypto pipeline blocks it (Invalid Signature Warning,
 *             Tampering Detected, DOMPurify strips the script)
 *
 * Results are narrated below the buttons with the exact verdict to look for,
 * and every run shows up in the Live Transport & Packet Inspector on the
 * right (including the red ATTACK step for the MITM interception).
 */

import { useState } from "react";
import { Bug, Loader2, Shuffle, Skull, Swords } from "lucide-react";
import { useMailStore } from "@/store/MailStoreContext";
import { useSecurityMode } from "@/store/SecurityModeContext";
import {
  mitmEmailDraft,
  spoofedEmailDraft,
  xssEmailDraft,
  type AttackId,
} from "@/lib/attacks";

interface AttackLabProps {
  /** Called after a successful attack send so the mailbox can show the result. */
  onAttackSent: () => void;
}

const ATTACKS: {
  id: AttackId;
  label: string;
  icon: typeof Bug;
}[] = [
  { id: "spoof", label: "Spoofed Email Attack", icon: Skull },
  { id: "mitm", label: "MITM Tampering", icon: Shuffle },
  { id: "xss", label: "Stored XSS Injection", icon: Bug },
];

interface AttackOutcome {
  /** "vulnerable" = the attack worked; "defended" = the defense stopped it. */
  tone: "vulnerable" | "defended";
  text: string;
}

/** Mode-aware narration of what just happened / what to look for. */
function outcomeFor(attack: AttackId, isSecure: boolean): AttackOutcome {
  if (attack === "spoof") {
    return isSecure
      ? {
          tone: "defended",
          text: "Signed with YOUR key while claiming admin@bank.com. Open the message → red INVALID SIGNATURE WARNING: the signing key does not match the bank's published directory key.",
        }
      : {
          tone: "vulnerable",
          text: "Accepted cleanly — the server stored admin@bank.com as sender without verifying anything. Open it: it reads normally with no signature warning.",
        };
  }

  if (attack === "mitm") {
    return isSecure
      ? {
          tone: "defended",
          text: "Attacker altered 1 base64 character of the ciphertext in transit (see the red ATTACK step and the POST body in the inspector). On receive, AES-GCM authentication fails → Tampering Detected.",
        }
      : {
          tone: "vulnerable",
          text: "Altered 1 character of the plaintext body in transit ($100 → $900). Unsafe mode has no integrity check — the recipient reads the tampered text as genuine.",
        };
  }

  return isSecure
    ? {
        tone: "defended",
        text: "Encrypted + signed in transit; on render DOMPurify strips the onerror handler. Open it — the alert never fires (check the SANITIZE step in the inspector).",
      }
    : {
        tone: "vulnerable",
        text: "Raw payload delivered. Open the message: the script executes inside your session (simulated hijack alert).",
      };
}

export default function AttackLab({ onAttackSent }: AttackLabProps) {
  const { sendDraft } = useMailStore();
  const { mode, isSecure } = useSecurityMode();
  const [busy, setBusy] = useState<AttackId | null>(null);
  const [result, setResult] = useState<(AttackOutcome & { attack: AttackId }) | null>(
    null,
  );

  async function run(attack: AttackId) {
    setBusy(attack);
    setResult(null);
    try {
      const draft =
        attack === "spoof"
          ? spoofedEmailDraft()
          : attack === "mitm"
            ? mitmEmailDraft()
            : xssEmailDraft();

      const sent = await sendDraft(
        draft,
        attack === "mitm" ? { tamper: true } : undefined,
      );

      if (!sent) {
        setResult({
          attack,
          tone: "vulnerable",
          text: "Send failed — check the compose panel for the error (in Secure Mode a recipient must have a registered directory key).",
        });
        return;
      }

      onAttackSent(); // jump the mailbox to the inbox so the result is visible
      setResult({ attack, ...outcomeFor(attack, isSecure) });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="border-b border-slate-800 bg-slate-950/70 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-slate-400">
          <Swords className="h-3.5 w-3.5 text-red-400" />
          Attack Lab
        </span>
        <span
          className={[
            "rounded px-1.5 py-0.5 text-[10px] font-bold uppercase",
            isSecure
              ? "bg-emerald-500/10 text-emerald-400"
              : "bg-red-500/10 text-red-400",
          ].join(" ")}
        >
          running in {mode} mode
        </span>

        <div className="ml-auto flex flex-wrap gap-1.5">
          {ATTACKS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => void run(id)}
              disabled={busy !== null}
              title={`Run the ${label} simulation in ${mode} mode`}
              className={[
                "flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-semibold transition-colors",
                busy === id
                  ? "border-red-500/60 bg-red-500/20 text-red-200"
                  : "border-red-500/40 bg-red-500/10 text-red-300 hover:bg-red-500/20",
                "disabled:cursor-not-allowed disabled:opacity-60",
              ].join(" ")}
            >
              {busy === id ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Icon className="h-3.5 w-3.5" />
              )}
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Outcome narration */}
      {result && (
        <p
          className={[
            "mt-2 rounded-md border px-3 py-2 text-xs leading-relaxed",
            result.tone === "defended"
              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
              : "border-red-500/50 bg-red-500/10 text-red-300",
          ].join(" ")}
        >
          <b>
            {result.tone === "defended"
              ? "SIMULATION BLOCKED — DEFENDED:"
              : "SIMULATION SUCCEEDED — VULNERABLE:"}
          </b>{" "}
          {result.text}
        </p>
      )}
    </div>
  );
}
