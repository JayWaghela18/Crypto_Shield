"use client";

/**
 * ⚔ Attack simulation deck.
 *
 * Each card runs the same attack in whichever mode is active, so the pair of
 * outcomes teaches the contrast:
 *
 *   UNSAFE  → the attack succeeds silently (accepted / reads normally / executes)
 *   SECURE  → the crypto pipeline blocks it (invalid signature, GCM failure,
 *             DOMPurify stripping)
 *
 * A red ATTACK step appears in the transport inspector for every run.
 */

import { useState } from "react";
import {
  Ban,
  Bug,
  CheckCircle2,
  Loader2,
  Play,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Swords,
} from "lucide-react";
import { useAuth } from "@/store/AuthContext";
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
  code: string;
  detail: string;
  icon: typeof Bug;
}[] = [
  {
    id: "spoof",
    label: "Certificate Spoofing",
    code: "ATK-01",
    detail: "Send as admin@bank.com without their private key.",
    icon: Ban,
  },
  {
    id: "mitm",
    label: "MITM Tampering",
    code: "ATK-02",
    detail: "Alter one character in transit, then forward.",
    icon: Bug,
  },
  {
    id: "xss",
    label: "XSS Payload Injection",
    code: "ATK-03",
    detail: "Embed an <img onerror> script in the body.",
    icon: Siren,
  },
];

interface AttackOutcome {
  tone: "vulnerable" | "defended";
  text: string;
}

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
        text: "Encrypted + signed in transit; on render DOMPurify strips the onerror handler. Open it — the script never runs (check the SANITIZE step in the inspector).",
      }
    : {
        tone: "vulnerable",
        text: "Raw payload delivered. Open the message: the script executes inside your session (simulated hijack alert).",
      };
}

export default function AttackLab({ onAttackSent }: AttackLabProps) {
  const { account } = useAuth();
  const { sendDraft } = useMailStore();
  const { mode, isSecure } = useSecurityMode();
  const [busy, setBusy] = useState<AttackId | null>(null);
  const [result, setResult] = useState<(AttackOutcome & { attack: AttackId }) | null>(null);

  async function run(attack: AttackId) {
    if (!account) return;
    setBusy(attack);
    setResult(null);
    try {
      const self = account.email;
      const draft =
        attack === "spoof"
          ? spoofedEmailDraft(self)
          : attack === "mitm"
            ? mitmEmailDraft(self)
            : xssEmailDraft(self);

      const sent = await sendDraft(
        draft,
        attack === "mitm" ? { tamper: true } : undefined,
      );

      if (!sent) {
        setResult({
          attack,
          tone: "vulnerable",
          text: "Send failed — check the compose panel for the error (secure mode needs the recipient's published key).",
        });
        return;
      }

      onAttackSent();
      setResult({ attack, ...outcomeFor(attack, isSecure) });
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="border-b border-slate-800/80 bg-slate-950/60 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-[0.18em] text-slate-400">
          <Swords className="h-3.5 w-3.5 text-rose-400" />
          attack simulation deck
        </span>
        <span
          className={[
            "chip ring-1",
            isSecure
              ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30"
              : "bg-rose-500/10 text-rose-300 ring-rose-500/30",
          ].join(" ")}
        >
          {isSecure ? <ShieldCheck className="h-2.5 w-2.5" /> : <ShieldAlert className="h-2.5 w-2.5" />}
          {mode} mode
        </span>
        <span className="ml-auto hidden font-mono text-[10px] text-slate-600 sm:block">
          payloads are contained to this local lab
        </span>
      </div>

      <div className="mt-2.5 grid gap-2 sm:grid-cols-3">
        {ATTACKS.map(({ id, label, code, detail, icon: Icon }) => {
          const running = busy === id;
          return (
            <div
              key={id}
              className="group relative overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/40 p-3 transition-all hover:border-rose-500/40 hover:bg-rose-500/[0.05]"
            >
              <div className="flex items-center gap-2">
                <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-rose-500/10 text-rose-400 ring-1 ring-rose-500/20">
                  <Icon className="h-3.5 w-3.5" />
                </span>
                <p className="text-[11px] font-bold leading-tight text-slate-200">{label}</p>
                <span className="ml-auto font-mono text-[9px] text-slate-600">{code}</span>
              </div>
              <p className="mt-1.5 text-[10px] leading-relaxed text-slate-500">{detail}</p>

              <div className="mt-2 flex items-center gap-2 text-[9px] font-bold uppercase tracking-wider">
                <span className="flex items-center gap-1 text-emerald-400/90">
                  <CheckCircle2 className="h-2.5 w-2.5" /> secure: blocked
                </span>
                <span className="flex items-center gap-1 text-rose-400/80">
                  <ShieldAlert className="h-2.5 w-2.5" /> unsafe: exploits
                </span>
              </div>

              <button
                type="button"
                onClick={() => void run(id)}
                disabled={busy !== null || !account}
                className="mt-2 flex w-full items-center justify-center gap-1.5 rounded-md border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-rose-200 transition-colors hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {running ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Play className="h-2.5 w-2.5" />
                )}
                {running ? "executing…" : "run simulation"}
              </button>
            </div>
          );
        })}
      </div>

      {result && (
        <p
          className={[
            "mt-2.5 flex items-start gap-2 rounded-lg border px-3 py-2 text-[11px] leading-relaxed",
            result.tone === "defended"
              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
              : "border-rose-500/50 bg-rose-500/10 text-rose-300",
          ].join(" ")}
        >
          {result.tone === "defended" ? (
            <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          ) : (
            <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          )}
          <span>
            <b>
              {result.tone === "defended"
                ? "SIMULATION BLOCKED — DEFENDED:"
                : "SIMULATION SUCCEEDED — VULNERABLE:"}
            </b>{" "}
            {result.text}
          </span>
        </p>
      )}
    </section>
  );
}
