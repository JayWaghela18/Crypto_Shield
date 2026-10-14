"use client";

/**
 * Compose form.
 *
 * ⚠ The From field is a free-text input on purpose: the server never
 * verifies it (email spoofing demo). The UI even nudges you to try
 * impersonating someone.
 */

import { useState, type FormEvent } from "react";
import { Loader2, Send, TriangleAlert } from "lucide-react";
import { useMailStore } from "@/store/MailStoreContext";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { CURRENT_USER, DEMO_USERS } from "@/lib/constants";

export default function ComposeForm() {
  const { sendDraft, isLoading, error, notice, clearNotice } = useMailStore();
  const { isSecure } = useSecurityMode();

  const [sender, setSender] = useState(CURRENT_USER);
  const [recipient, setRecipient] = useState("bob@cryptoshield.dev");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    clearNotice();
    const sent = await sendDraft({ sender, recipient, subject, body });
    if (sent) {
      // Reset the form after an accepted send.
      setSubject("");
      setBody("");
    }
  }

  const fieldClass =
    "w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500";

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4 p-4">
      {/* Spoofable sender */}
      <label className="block">
        <span className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400">
          From
          {!isSecure && (
            <span className="flex items-center gap-1 text-red-400">
              <TriangleAlert className="h-3 w-3" />
              spoofable — server never verifies
            </span>
          )}
        </span>
        <input
          type="text"
          value={sender}
          onChange={(e) => setSender(e.target.value)}
          className={fieldClass}
          placeholder="anyone@any-domain.example"
          required
        />
      </label>

      <label className="block">
        <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-400">
          To
        </span>
        <select
          value={recipient}
          onChange={(e) => setRecipient(e.target.value)}
          className={fieldClass}
        >
          {DEMO_USERS.map((user) => (
            <option key={user.email} value={user.email}>
              {user.displayName} — {user.email}
            </option>
          ))}
        </select>
      </label>

      <label className="block">
        <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-400">
          Subject
        </span>
        <input
          type="text"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          className={fieldClass}
          placeholder="Subject"
        />
      </label>

      <label className="block flex-1">
        <span className="mb-1 flex items-center justify-between text-xs font-semibold uppercase tracking-wide text-slate-400">
          Body
          <span className={isSecure ? "text-emerald-400" : "text-red-400"}>
            {isSecure ? "secure mode" : "HTML allowed — raw on the wire"}
          </span>
        </span>
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          className={`${fieldClass} min-h-[180px] flex-1 resize-none font-mono text-xs`}
          placeholder={
            isSecure
              ? "Message body…"
              : "Message body… (HTML allowed — try <b>bold</b> or an img onerror payload to see Stored XSS)"
          }
          required
        />
      </label>

      {/* Status line */}
      {error && (
        <p className="rounded-md bg-red-500/10 px-3 py-2 text-xs text-red-400">{error}</p>
      )}
      {notice && (
        <p className="rounded-md bg-emerald-500/10 px-3 py-2 text-xs text-emerald-400">
          {notice}
        </p>
      )}

      <button
        type="submit"
        disabled={isLoading}
        className="flex items-center justify-center gap-2 rounded-md bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
        Send Message
      </button>
    </form>
  );
}
