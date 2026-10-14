"use client";

/**
 * Mailbox (left pane) — Inbox / Sent / Compose tabs plus a reading pane.
 *
 * Phase 2: selecting a message runs the receive pipeline
 * (useSecureMessage) — secure messages are decrypted, signature-verified
 * against the /api/keys directory, and sanitized before rendering, with a
 * green VERIFIED / red SPOOFED banner above the body.
 */

import { useEffect, useState } from "react";
import {
  ArrowLeft,
  Inbox,
  Loader2,
  Lock,
  MailOpen,
  PenLine,
  Send,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";
import type { EmailPayload, MailboxFolder } from "@/lib/types";
import { useMailStore } from "@/store/MailStoreContext";
import { useSecurityMode } from "@/store/SecurityModeContext";
import ComposeForm from "@/components/mailbox/ComposeForm";
import EmailBody from "@/components/mailbox/EmailBody";
import VerificationBanner from "@/components/mailbox/VerificationBanner";
import { useSecureMessage } from "@/components/mailbox/useSecureMessage";
import CertificateStatusControl from "@/components/mailbox/CertificateStatusControl";
import ExternalDecryptPanel from "@/components/mailbox/ExternalDecryptPanel";
import AttackLab from "@/components/attacks/AttackLab";

type Tab = MailboxFolder | "compose";

/** Strip HTML for the one-line list preview. */
function previewOf(html: string): string {
  return html
    .replace(/<[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function Mailbox() {
  const { emails, activeFolder, isLoading, loadFolder } = useMailStore();
  const { mode } = useSecurityMode();

  const [tab, setTab] = useState<Tab>("inbox");
  const [selected, setSelected] = useState<EmailPayload | null>(null);
  // Bumped when the CRL changes so the pipeline re-checks revocation.
  const [revocationVersion, setRevocationVersion] = useState(0);

  // Receive pipeline for the open message (decrypt → verify → bind → CRL → sanitize).
  const secureView = useSecureMessage(selected, revocationVersion);

  // Load a folder whenever the inbox/sent tab becomes active.
  useEffect(() => {
    if (tab !== "compose") void loadFolder(tab);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  function openTab(next: Tab) {
    setTab(next);
    if (next !== tab) setSelected(null);
  }

  const tabs: { id: Tab; label: string; icon: typeof Inbox }[] = [
    { id: "inbox", label: "Inbox", icon: Inbox },
    { id: "sent", label: "Sent", icon: Send },
    { id: "compose", label: "Compose", icon: PenLine },
  ];

  // What the reading pane shows: decrypted content for secure messages,
  // the raw fields for plaintext ones.
  const content =
    selected && (!selected.isSecureMode || secureView.payload) && selected.body !== undefined
      ? selected.isSecureMode
        ? secureView.payload
        : { subject: selected.subject, body: selected.body }
      : null;

  // After an attack simulation lands, show it: switch to the inbox and
  // refresh (or just refresh if the inbox tab is already active).
  function handleAttackSent() {
    setSelected(null);
    if (tab === "inbox") void loadFolder("inbox");
    else setTab("inbox"); // tab effect triggers the reload
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Phase 3: attack simulation triggers */}
      <AttackLab onAttackSent={handleAttackSent} />

      {/* Tab bar */}
      <nav className="flex items-center gap-1 border-b border-slate-800 bg-slate-900/50 px-4 py-2">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => openTab(id)}
            className={[
              "flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
              tab === id
                ? "bg-slate-700 text-white"
                : "text-slate-400 hover:bg-slate-800 hover:text-slate-200",
            ].join(" ")}
          >
            <Icon className="h-4 w-4" />
            {label}
          </button>
        ))}

        <span className="ml-auto flex items-center gap-1.5 text-xs text-slate-500">
          {mode === "secure" ? (
            <>
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
              E2E transport
            </>
          ) : (
            <>
              <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
              plaintext transport
            </>
          )}
        </span>
      </nav>

      {/* Body */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {tab === "compose" && <ComposeForm />}

        {tab !== "compose" && !selected && (
          <>
            {isLoading && emails.length === 0 && (
              <div className="flex items-center justify-center gap-2 p-8 text-sm text-slate-500">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading {tab}…
              </div>
            )}

            {!isLoading && emails.length === 0 && (
              <p className="p-8 text-center text-sm text-slate-500">
                No messages in {activeFolder}.
              </p>
            )}

            {/* Message list */}
            <ul className="divide-y divide-slate-800/70">
              {emails.map((email) => {
                const isEncrypted = email.isSecureMode;
                const hasLocalCopy = isEncrypted && email.localPlaintext;
                const preview =
                  isEncrypted && !hasLocalCopy
                    ? "🔒 Encrypted — open to decrypt, verify & sanitize"
                    : previewOf(email.body);

                return (
                  <li key={email.id}>
                    <button
                      onClick={() => setSelected(email)}
                      className="block w-full px-4 py-3 text-left transition-colors hover:bg-slate-900"
                    >
                      <div className="flex items-baseline justify-between gap-3">
                        <span className="truncate text-sm font-semibold text-slate-100">
                          {activeFolder === "inbox" ? email.sender : `→ ${email.recipient}`}
                        </span>
                        <span className="shrink-0 text-xs text-slate-500">
                          {formatTime(email.timestamp)}
                        </span>
                      </div>
                      <p className="truncate text-sm text-slate-300">
                        {email.subject || "(no subject)"}
                      </p>
                      <p className="truncate text-xs text-slate-500">{preview}</p>
                      <span
                        className={[
                          "mt-1 inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase",
                          isEncrypted
                            ? "bg-emerald-500/10 text-emerald-400"
                            : "bg-slate-700/50 text-slate-400",
                        ].join(" ")}
                      >
                        {isEncrypted && <Lock className="h-2.5 w-2.5" />}
                        {isEncrypted ? "E2E encrypted" : "plaintext"}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </>
        )}

        {/* Reading pane */}
        {tab !== "compose" && selected && (
          <div className="flex flex-col gap-4 p-4">
            <button
              onClick={() => setSelected(null)}
              className="flex w-fit items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-slate-200"
            >
              <ArrowLeft className="h-3.5 w-3.5" /> Back to {activeFolder}
            </button>

            <div>
              <h2 className="flex items-center gap-2 text-lg font-bold text-slate-100">
                <MailOpen className="h-4 w-4 text-slate-500" />
                {content?.subject || (selected.isSecureMode ? "(decrypting…)" : "(no subject)")}
              </h2>
              <div className="mt-1 flex flex-wrap gap-x-6 text-xs text-slate-400">
                <span>
                  From: <b className="text-slate-200">{selected.sender}</b>
                </span>
                <span>To: {selected.recipient}</span>
                <span>{formatTime(selected.timestamp)}</span>
              </div>

              {/* Spoof notice — only meaningful for plaintext messages;
                  secure messages get the signature banner below instead. */}
              {!selected.isSecureMode && (
                <p className="mt-2 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-[11px] text-amber-400">
                  ⚠ From-header authenticity is NOT verified in this mode — display name
                  and address can be forged (email spoofing).
                </p>
              )}
            </div>

            {/* Phase 2: verification verdict (green / red / amber) */}
            <VerificationBanner
              verification={secureView.verification}
              working={selected.isSecureMode && secureView.phase !== "done"}
            />

            {/* CRL simulation toggle + imported-key decryption tester */}
            {mode === "secure" && selected.isSecureMode && (
              <>
                <CertificateStatusControl
                  address={selected.sender}
                  onChanged={() => setRevocationVersion((v) => v + 1)}
                />
                <ExternalDecryptPanel email={selected} />
              </>
            )}

            {/* Dual-mode body rendering (decrypted content for secure mail) */}
            {selected.isSecureMode && !content && secureView.phase !== "done" && (
              <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-sm text-slate-400">
                <Loader2 className="h-4 w-4 animate-spin" /> Decrypting with your private
                key…
              </div>
            )}

            {selected.isSecureMode && !content && secureView.phase === "done" && (
              <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-300">
                Content unavailable — the message could not be decrypted or authenticated.
                See the verification banner above.
              </div>
            )}

            {content && <EmailBody html={content.body} mode={mode} />}

            {/* Raw payload readout (what the server can actually see) */}
            <details className="rounded-lg border border-slate-800 bg-slate-900/40">
              <summary className="cursor-pointer px-4 py-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
                {selected.isSecureMode
                  ? "Server copy (opaque envelope — unreadable without your key)"
                  : "Raw EmailPayload (server copy)"}
              </summary>
              <pre className="overflow-x-auto border-t border-slate-800 p-4 text-[11px] leading-relaxed text-slate-400">
                {JSON.stringify(selected, null, 2)}
              </pre>
            </details>
          </div>
        )}
      </div>
    </div>
  );
}
