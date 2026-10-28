"use client";

/**
 * Compose form.
 *
 * ⚠ The From field stays editable on purpose: the unsafe engine never verifies
 * it (email-spoofing demo). In secure mode the signature exposes the forgery,
 * because the directory binding compares the signing key to the claimed
 * sender's published key.
 */

import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  AtSign,
  Lock,
  Loader2,
  Mail,
  Send,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import type { DirectoryEntry } from "@/lib/types";
import { fetchDirectoryList } from "@/lib/api/emailClient";
import { DEMO_USERS } from "@/lib/constants";
import { useAuth } from "@/store/AuthContext";
import { useMailStore } from "@/store/MailStoreContext";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useTransport } from "@/store/TransportContext";

export default function ComposeForm() {
  const { account } = useAuth();
  const { sendDraft, isLoading, error, notice, clearNotice } = useMailStore();
  const { mode, isSecure } = useSecurityMode();
  const { recordPacket } = useTransport();

  const [sender, setSender] = useState(account?.email ?? "");
  const [recipient, setRecipient] = useState("bob@cryptoshield.dev");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [directory, setDirectory] = useState<DirectoryEntry[]>([]);

  useEffect(() => {
    if (account) setSender(account.email);
  }, [account]);

  useEffect(() => {
    let cancelled = false;
    fetchDirectoryList(mode, recordPacket)
      .then((entries) => {
        if (!cancelled) setDirectory(entries);
      })
      .catch(() => {
        if (!cancelled) setDirectory([]);
      });
    return () => {
      cancelled = true;
    };
  }, [mode, recordPacket]);

  const recipients = useMemo(() => {
    const map = new Map<string, string>();
    for (const user of DEMO_USERS) map.set(user.email, user.displayName);
    for (const entry of directory) {
      map.set(entry.address, entry.name ?? entry.address);
    }
    return [...map.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  }, [directory]);

  const recipientEntry = directory.find(
    (entry) => entry.address.toLowerCase() === recipient.trim().toLowerCase(),
  );

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    clearNotice();
    const sent = await sendDraft({ sender, recipient, subject, body });
    if (sent) {
      setSubject("");
      setBody("");
    }
  }

  return (
    <form onSubmit={handleSubmit} className="mx-auto w-full max-w-3xl space-y-4 px-4 py-5">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="eyebrow">New transmission</p>
          <h2 className="mt-0.5 text-lg font-bold tracking-tight">Compose secure mail</h2>
        </div>
        <span
          className={[
            "chip ring-1",
            isSecure
              ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30"
              : "bg-rose-500/10 text-rose-300 ring-rose-500/30",
          ].join(" ")}
        >
          {isSecure ? <ShieldCheck className="h-2.5 w-2.5" /> : <TriangleAlert className="h-2.5 w-2.5" />}
          {isSecure ? "E2EE envelope" : "plaintext transport"}
        </span>
      </header>

      <div className="glass rounded-2xl">
        <div className="grid gap-4 border-b border-slate-800/80 p-4 sm:grid-cols-2">
          <label className="block">
            <span className="mb-1 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
              From
              {!isSecure && (
                <span className="flex items-center gap-1 text-rose-400/90 normal-case tracking-normal">
                  <TriangleAlert className="h-2.5 w-2.5" /> spoofable
                </span>
              )}
            </span>
            <input
              type="text"
              value={sender}
              onChange={(event) => setSender(event.target.value)}
              className="input-cyber font-mono text-xs"
              placeholder="anyone@any-domain.example"
              required
            />
          </label>

          <label className="block">
            <span className="mb-1 flex items-center justify-between text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
              To
              {recipientEntry && (
                <span className="key-badge normal-case tracking-normal">
                  {isSecure ? "key found" : "addressable"}
                </span>
              )}
            </span>
            <select
              value={recipient}
              onChange={(event) => setRecipient(event.target.value)}
              className="input-cyber text-xs"
            >
              {recipients.map(([email, name]) => (
                <option key={email} value={email}>
                  {name} — {email}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="border-b border-slate-800/80 px-4 py-3">
          <input
            type="text"
            value={subject}
            onChange={(event) => setSubject(event.target.value)}
            className="w-full border-none bg-transparent text-sm font-semibold text-slate-100 placeholder-slate-600 outline-none"
            placeholder="Subject"
          />
        </div>

        <div className="p-4">
          <textarea
            value={body}
            onChange={(event) => setBody(event.target.value)}
            className="min-h-[220px] w-full resize-y border-none bg-transparent font-mono text-xs leading-relaxed text-slate-200 placeholder-slate-600 outline-none"
            placeholder={
              isSecure
                ? "Message body… it will be AES-256-GCM encrypted and RSA-PSS signed before it leaves this tab."
                : "Message body… HTML allowed. Try <b>bold</b> or an img onerror payload to see Stored XSS."
            }
            required
          />
        </div>

        <footer className="flex flex-wrap items-center gap-2 border-t border-slate-800/80 bg-slate-950/40 px-4 py-3">
          <p className="flex items-center gap-1.5 font-mono text-[10px] text-slate-500">
            {isSecure ? (
              <>
                <Lock className="h-3 w-3 text-emerald-400" />
                AES-256-GCM → RSA-OAEP → RSA-PSS
              </>
            ) : (
              <>
                <AtSign className="h-3 w-3 text-rose-400" />
                raw JSON · no signature · no integrity
              </>
            )}
          </p>
          <button type="submit" disabled={isLoading} className="btn-primary ml-auto">
            {isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : isSecure ? (
              <Lock className="h-4 w-4" />
            ) : (
              <Send className="h-4 w-4" />
            )}
            {isSecure ? "Encrypt & send" : "Send plaintext"}
          </button>
        </footer>
      </div>

      {error && (
        <p className="flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
          <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          {error}
        </p>
      )}
      {notice && (
        <p className="flex items-start gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
          <Mail className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          {notice}
        </p>
      )}
    </form>
  );
}
