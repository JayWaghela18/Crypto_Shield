"use client";

/**
 * Mailbox (left pane) — Inbox / Sent / Compose plus a reading pane.
 *
 * Every view is filtered to the ACTIVE account's address. Selecting a message
 * runs the receive pipeline (useSecureMessage): decrypt → verify → directory
 * bind → CRL check → sanitize, with a verdict banner and a per-card badge.
 *
 * The reading pane can flip between the decrypted view and the raw wire
 * envelope, making the difference between ciphertext and plaintext tangible.
 */

import { useEffect, useState } from "react";
import {
  ArrowLeft,
  BadgeCheck,
  Ban,
  ChevronRight,
  Inbox,
  Loader2,
  Lock,
  LockOpen,
  MailOpen,
  PenLine,
  Radio,
  Send,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  ShieldQuestion,
  Sparkles,
  Terminal,
  TriangleAlert,
  UserRound,
  X,
} from "lucide-react";
import type { EmailPayload, MailboxFolder, VerificationStatus } from "@/lib/types";
import { DEMO_USERS } from "@/lib/constants";
import { useAuth } from "@/store/AuthContext";
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
type MailView = "decrypted" | "raw";

function previewOf(html: string): string {
  return html
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 140);
}

function formatTime(ts: number): string {
  return new Date(ts)
    .toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    })
    .toUpperCase();
}

function displayNameFor(address: string): string {
  const known = DEMO_USERS.find(
    (user) => user.email.toLowerCase() === address.toLowerCase(),
  );
  if (known) return known.displayName;
  const local = address.split("@")[0] ?? address;
  return local
    .split(/[._-]/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function initialsFor(address: string): string {
  const words = displayNameFor(address)
    .replace(/\(.*?\)/g, "")
    .split(/\s+/)
    .filter((word) => /[a-z]/i.test(word));
  if (words.length === 0) return "??";
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return `${words[0][0]}${words[1][0]}`.toUpperCase();
}

const AVATAR_TONES = [
  "from-cyan-500/30 to-sky-500/10 text-cyan-200 ring-cyan-400/20",
  "from-emerald-500/30 to-teal-500/10 text-emerald-200 ring-emerald-400/20",
  "from-violet-500/30 to-fuchsia-500/10 text-violet-200 ring-violet-400/20",
  "from-amber-500/30 to-orange-500/10 text-amber-200 ring-amber-400/20",
  "from-rose-500/30 to-pink-500/10 text-rose-200 ring-rose-400/20",
];

function toneFor(address: string): string {
  let hash = 0;
  for (let i = 0; i < address.length; i += 1) hash = (hash * 31 + address.charCodeAt(i)) >>> 0;
  return AVATAR_TONES[hash % AVATAR_TONES.length];
}

/** Badge shown on each message card, driven by the last verification verdict. */
function MessageBadge({
  email,
  verdict,
}: {
  email: EmailPayload;
  verdict?: VerificationStatus;
}) {
  if (!email.isSecureMode) {
    return (
      <span className="chip border border-amber-500/30 bg-amber-500/10 text-amber-300">
        <ShieldQuestion className="h-2.5 w-2.5" /> plaintext
      </span>
    );
  }

  if (verdict === "verified" || email.localPlaintext) {
    return (
      <span className="chip border border-emerald-500/30 bg-emerald-500/10 text-emerald-300">
        <BadgeCheck className="h-2.5 w-2.5" /> verified rsa-pss
      </span>
    );
  }
  if (verdict === "revoked") {
    return (
      <span className="chip border border-orange-500/40 bg-orange-500/10 text-orange-300">
        <ShieldOff className="h-2.5 w-2.5" /> revoked cert
      </span>
    );
  }
  if (verdict === "spoofed-tampered") {
    return (
      <span className="chip border border-rose-500/40 bg-rose-500/10 text-rose-300">
        <ShieldAlert className="h-2.5 w-2.5" /> tampered aes
      </span>
    );
  }
  if (verdict === "spoofed-unverified") {
    return (
      <span className="chip border border-rose-500/40 bg-rose-500/10 text-rose-300">
        <Ban className="h-2.5 w-2.5" /> unverified sig
      </span>
    );
  }
  return (
    <span className="chip border border-cyan-400/25 bg-cyan-400/[0.07] text-cyan-200">
      <Lock className="h-2.5 w-2.5" /> sealed rsa-pss
    </span>
  );
}

export default function Mailbox() {
  const { account } = useAuth();
  const { emails, activeFolder, isLoading, loadFolder, error } = useMailStore();
  const { mode } = useSecurityMode();

  const [tab, setTab] = useState<Tab>("inbox");
  const [selected, setSelected] = useState<EmailPayload | null>(null);
  const [view, setView] = useState<MailView>("decrypted");
  const [revocationVersion, setRevocationVersion] = useState(0);
  const [verdicts, setVerdicts] = useState<Record<string, VerificationStatus>>({});

  const secureView = useSecureMessage(selected, revocationVersion);

  // Persist the verdict onto the list badge as soon as the pipeline finishes.
  useEffect(() => {
    if (!selected || secureView.phase !== "done" || !secureView.verification) return;
    const messageId = selected.id;
    const verdict = secureView.verification.status;
    setVerdicts((current) =>
      current[messageId] === verdict ? current : { ...current, [messageId]: verdict },
    );
  }, [selected, secureView.phase, secureView.verification]);

  // Reset the reading pane when switching profiles.
  useEffect(() => {
    setSelected(null);
    setTab("inbox");
    setVerdicts({});
  }, [account?.email]);

  useEffect(() => {
    if (tab !== "compose" && account) void loadFolder(tab);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, account?.email]);

  function openTab(next: Tab) {
    setTab(next);
    setSelected(null);
  }

  function openMessage(email: EmailPayload) {
    setSelected(email);
    setView("decrypted");
  }

  const tabs: { id: Tab; label: string; icon: typeof Inbox }[] = [
    { id: "inbox", label: "Inbox", icon: Inbox },
    { id: "sent", label: "Sent", icon: Send },
    { id: "compose", label: "Compose", icon: PenLine },
  ];

  const decryptedContent =
    selected && (!selected.isSecureMode || secureView.payload)
      ? selected.isSecureMode
        ? secureView.payload
        : { subject: selected.subject, body: selected.body }
      : null;

  function handleAttackSent() {
    setSelected(null);
    if (tab === "inbox") void loadFolder("inbox");
    else setTab("inbox");
  }

  if (!account) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-2 p-8 text-center">
        <LockOpen className="h-6 w-6 text-slate-600" />
        <p className="text-sm text-slate-400">Authenticate to open your mailbox.</p>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <AttackLab onAttackSent={handleAttackSent} />

      {/* Folder bar */}
      <nav className="flex flex-wrap items-center gap-2 border-b border-slate-800/80 bg-slate-950/70 px-3 py-2">
        <div className="flex items-center gap-0.5 rounded-lg border border-slate-800/80 bg-slate-900/50 p-0.5">
          {tabs.map(({ id, label, icon: Icon }) => {
            const active = tab === id;
            return (
              <button
                key={id}
                onClick={() => openTab(id)}
                className={[
                  "relative flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[11px] font-bold transition-all",
                  active
                    ? "bg-slate-800 text-cyan-200 shadow-innerline"
                    : "text-slate-500 hover:text-slate-300",
                ].join(" ")}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
                {active && tab !== "compose" && (
                  <span className="rounded bg-cyan-400/15 px-1 font-mono text-[9px] text-cyan-200">
                    {emails.length}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        <p className="ml-auto hidden items-center gap-1.5 font-mono text-[10px] text-slate-600 md:flex">
          <UserRound className="h-3 w-3" />
          filtered → <span className="text-slate-400">{account.email}</span>
        </p>
        <span
          className={[
            "chip ring-1",
            mode === "secure"
              ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30"
              : "bg-rose-500/10 text-rose-300 ring-rose-500/30",
          ].join(" ")}
        >
          {mode === "secure" ? (
            <ShieldCheck className="h-2.5 w-2.5" />
          ) : (
            <TriangleAlert className="h-2.5 w-2.5" />
          )}
          {mode === "secure" ? "e2ee transport" : "plaintext transport"}
        </span>
      </nav>

      {/* Body */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {error && (
          <p className="m-3 flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-[11px] text-rose-300">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            {error}
          </p>
        )}

        {tab === "compose" && <ComposeForm />}

        {tab !== "compose" && !selected && (
          <>
            {isLoading && emails.length === 0 && (
              <div className="flex items-center justify-center gap-2 p-10 font-mono text-[11px] text-slate-500">
                <Loader2 className="h-4 w-4 animate-spin text-cyan-300" />
                syncing {tab} envelope store…
              </div>
            )}

            {!isLoading && emails.length === 0 && (
              <div className="flex flex-col items-center justify-center gap-2 p-12 text-center">
                <MailOpen className="h-7 w-7 text-slate-700" />
                <p className="text-sm font-semibold text-slate-400">
                  {activeFolder === "inbox" ? "Inbox zero" : "Nothing sent yet"}
                </p>
                <p className="max-w-xs text-[11px] leading-relaxed text-slate-600">
                  Mail is filtered to <span className="text-slate-400">{account.email}</span>.
                  Compose a message or switch profiles to see the other side.
                </p>
                <button
                  onClick={() => openTab(activeFolder === "inbox" ? "compose" : "inbox")}
                  className="btn-ghost mt-1"
                >
                  {activeFolder === "inbox" ? <PenLine className="h-3.5 w-3.5" /> : <Inbox className="h-3.5 w-3.5" />}
                  {activeFolder === "inbox" ? "Compose mail" : "Back to inbox"}
                </button>
              </div>
            )}

            <ul className="divide-y divide-slate-800/60">
              {emails.map((email) => {
                const outgoing = activeFolder === "sent";
                const peer = outgoing ? email.recipient : email.sender;
                const preview =
                  email.isSecureMode && !email.localPlaintext
                    ? "◆ sealed envelope — open to decrypt, verify and sanitize"
                    : previewOf(email.body);

                return (
                  <li key={email.id}>
                    <button
                      onClick={() => openMessage(email)}
                      className="group flex w-full items-start gap-3 px-3 py-3 text-left transition-colors hover:bg-slate-900/70"
                    >
                      <span
                        className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br text-[11px] font-black ring-1 ${toneFor(peer)}`}
                      >
                        {initialsFor(peer)}
                      </span>

                      <span className="min-w-0 flex-1">
                        <span className="flex items-baseline gap-2">
                          <span className="truncate text-xs font-bold text-slate-100">
                            {outgoing ? `→ ${displayNameFor(peer)}` : displayNameFor(peer)}
                          </span>
                          <span className="hidden truncate font-mono text-[9px] text-slate-600 sm:inline">
                            {peer}
                          </span>
                          <span className="ml-auto shrink-0 font-mono text-[9px] text-slate-600">
                            {formatTime(email.timestamp)}
                          </span>
                        </span>
                        <span className="mt-0.5 flex items-center gap-1.5">
                          <span className="truncate text-[12px] font-medium text-slate-300">
                            {email.subject || "(no subject)"}
                          </span>
                          {email.localPlaintext && (
                            <span className="chip bg-slate-800 text-slate-500">local copy</span>
                          )}
                        </span>
                        <span className="mt-0.5 block truncate text-[10px] text-slate-500">
                          {preview}
                        </span>
                        <span className="mt-1.5 flex items-center gap-1.5">
                          <MessageBadge email={email} verdict={verdicts[email.id]} />
                          <ChevronRight className="ml-auto h-3 w-3 text-slate-700 transition-transform group-hover:translate-x-0.5 group-hover:text-cyan-300" />
                        </span>
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
          <div className="animate-fadein space-y-3 p-3 sm:p-4">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setSelected(null)}
                className="flex items-center gap-1.5 rounded-lg border border-slate-800/80 bg-slate-900/50 px-2.5 py-1 text-[11px] font-semibold text-slate-400 transition-colors hover:border-slate-700 hover:text-slate-200"
              >
                <ArrowLeft className="h-3 w-3" /> {activeFolder}
              </button>
              <span className="font-mono text-[9px] text-slate-600">
                ID {selected.id.slice(0, 8).toUpperCase()}
              </span>
              <button
                onClick={() => setSelected(null)}
                aria-label="Close message"
                className="ml-auto rounded-lg p-1 text-slate-600 hover:text-slate-300"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>

            <header className="rounded-xl border border-slate-800/80 bg-slate-900/40 px-4 py-3">
              <div className="flex flex-wrap items-center gap-1.5">
                <MessageBadge email={selected} verdict={verdicts[selected.id]} />
                <span className="chip bg-slate-800 text-slate-400">
                  <Radio className="h-2.5 w-2.5" /> {selected.isSecureMode ? "hybrid envelope" : "raw json"}
                </span>
                <span className="ml-auto font-mono text-[10px] text-slate-600">
                  {formatTime(selected.timestamp)}
                </span>
              </div>

              <h2 className="mt-2 flex items-start gap-2 text-lg font-bold leading-snug tracking-tight text-slate-100">
                <MailOpen className="mt-1 h-4 w-4 shrink-0 text-slate-600" />
                {decryptedContent?.subject ||
                  (selected.isSecureMode ? "(decrypting subject…)" : "(no subject)")}
              </h2>

              <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-500">
                <span>
                  From:{" "}
                  <b className="font-mono text-[10px] font-medium text-slate-300">
                    {selected.sender}
                  </b>
                </span>
                <span>
                  To:{" "}
                  <b className="font-mono text-[10px] font-medium text-slate-300">
                    {selected.recipient}
                  </b>
                </span>
              </div>

              {!selected.isSecureMode && (
                <p className="mt-2 flex items-start gap-1.5 rounded-lg border border-amber-500/25 bg-amber-500/[0.07] px-2.5 py-1.5 text-[10px] leading-relaxed text-amber-300/90">
                  <TriangleAlert className="mt-px h-3 w-3 shrink-0" />
                  The From header is not verified in this mode — display name and address
                  can be forged (email spoofing).
                </p>
              )}
            </header>

            <VerificationBanner
              verification={secureView.verification}
              working={selected.isSecureMode && secureView.phase !== "done"}
            />

            {secureView.sanitization?.stripped && (
              <p className="flex items-start gap-2 rounded-xl border border-cyan-400/40 bg-cyan-400/[0.07] px-3.5 py-2.5 text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-200">
                <Sparkles className="mt-px h-3.5 w-3.5 shrink-0" />
                XSS payload neutralized · DOMPurify removed {" "}
                {secureView.sanitization.removedChars} unsafe characters before render
              </p>
            )}

            {/* Decrypted ⇄ raw wire toggle */}
            <div className="flex items-center gap-2">
              <div className="flex rounded-lg border border-slate-800/80 bg-slate-950/70 p-0.5">
                {(
                  [
                    { id: "decrypted" as const, label: "Decrypted view", icon: LockOpen },
                    { id: "raw" as const, label: "Raw wire envelope", icon: Terminal },
                  ]
                ).map(({ id, label, icon: Icon }) => (
                  <button
                    key={id}
                    onClick={() => setView(id)}
                    className={[
                      "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider transition-all",
                      view === id
                        ? "bg-slate-800 text-cyan-200"
                        : "text-slate-500 hover:text-slate-300",
                    ].join(" ")}
                  >
                    <Icon className="h-3 w-3" />
                    {label}
                  </button>
                ))}
              </div>
              <span className="font-mono text-[9px] text-slate-600">
                {view === "decrypted" ? "plaintext after local unwrap" : "what the relay stores"}
              </span>
            </div>

            {view === "decrypted" ? (
              <>
                {selected.isSecureMode && !decryptedContent && secureView.phase !== "done" && (
                  <div className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/50 p-4 text-xs text-slate-400">
                    <Loader2 className="h-4 w-4 animate-spin text-cyan-300" />
                    Unwrapping the AES key with your RSA-OAEP private key…
                  </div>
                )}

                {selected.isSecureMode && !decryptedContent && secureView.phase === "done" && (
                  <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-xs text-rose-300">
                    Content unavailable — the envelope could not be decrypted or
                    authenticated. See the verification banner above.
                  </div>
                )}

                {decryptedContent && (
                  <EmailBody html={decryptedContent.body} mode={mode} />
                )}
              </>
            ) : (
              <RawWireView email={selected} />
            )}

            {mode === "secure" && selected.isSecureMode && (
              <>
                <CertificateStatusControl
                  address={selected.sender}
                  onChanged={() => setRevocationVersion((value) => value + 1)}
                />
                <ExternalDecryptPanel email={selected} />
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/** Terminal-style readout of the exact fields the server keeps. */
function RawWireView({ email }: { email: EmailPayload }) {
  const envelope = {
    v: 1,
    sender: email.sender,
    recipient: email.recipient,
    subject: email.subject,
    isSecureMode: email.isSecureMode,
    body: email.isSecureMode ? "" : email.body,
    payloadCiphertext: email.ciphertext,
    encryptedSymmetricKey: email.symmetricKey,
    signature: email.signature,
    senderPubKey: email.senderPubKey
      ? {
          encryption: `{kty:${email.senderPubKey.encryption.kty}, n:${email.senderPubKey.encryption.n?.slice(0, 24)}…}`,
          signing: `{kty:${email.senderPubKey.signing.kty}, n:${email.senderPubKey.signing.n?.slice(0, 24)}…}`,
        }
      : null,
    timestamp: email.timestamp,
  };

  const text = JSON.stringify(envelope, null, 2);

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-950/90">
      <div className="flex items-center gap-2 border-b border-slate-800/80 px-3 py-2">
        <span className="h-2 w-2 rounded-full bg-rose-500/80" />
        <span className="h-2 w-2 rounded-full bg-amber-500/80" />
        <span className="h-2 w-2 rounded-full bg-emerald-500/80" />
        <span className="ml-2 font-mono text-[10px] text-slate-500">
          relay-store / {email.id.slice(0, 8)}.json
        </span>
        <span className="ml-auto chip bg-slate-800 text-slate-500">
          {email.isSecureMode ? "opaque to server" : "server can read this"}
        </span>
      </div>
      <pre className="max-h-[420px] overflow-auto p-3 font-mono text-[10.5px] leading-relaxed text-emerald-300/80">
        {text}
      </pre>
      {email.isSecureMode && (
        <p className="border-t border-slate-800/80 px-3 py-2 font-mono text-[9.5px] text-slate-600">
          # the AES key inside encryptedSymmetricKey is wrapped to the recipient&apos;s
          RSA-OAEP public key — only their private key can open it
        </p>
      )}
    </div>
  );
}
