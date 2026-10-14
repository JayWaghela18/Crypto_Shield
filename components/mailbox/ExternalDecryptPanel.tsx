"use client";

/**
 * Third-party decryption tester.
 *
 * When an external key has been imported (Key Management), this panel lets the
 * user attempt to decrypt the selected secure message with THAT private key —
 * the situation where you hold someone else's private key out of band and want
 * to prove whether the envelope was addressed to it.
 *
 * The full receive pipeline still runs (unwrap → decrypt → verify → bind), so a
 * message encrypted to a different recipient reports `failedStage: "unwrap"`.
 */

import { useState } from "react";
import { KeyRound, Loader2 } from "lucide-react";
import type { EmailPayload, VerificationResult } from "@/lib/types";
import { decryptAndVerify } from "@/lib/crypto";
import { fetchDirectoryKey } from "@/lib/api/emailClient";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useTransport } from "@/store/TransportContext";
import { useAudit } from "@/store/AuditContext";
import { useKeyVault } from "@/store/KeyVaultContext";

interface AttemptResult {
  ok: boolean;
  verification?: VerificationResult;
  body?: string | null;
  note?: string;
}

export default function ExternalDecryptPanel({ email }: { email: EmailPayload }) {
  const { imported } = useKeyVault();
  const { mode } = useSecurityMode();
  const { recordPacket, recordCryptoStep } = useTransport();
  const { recordIncident } = useAudit();

  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<AttemptResult | null>(null);

  if (!imported || !email.isSecureMode) return null;

  async function attemptDecrypt() {
    setBusy(true);
    setResult(null);
    try {
      // Directory lookup is best-effort — a third-party identity is often not
      // registered, which is exactly what the binding check reports.
      let directory = null;
      try {
        directory = await fetchDirectoryKey(email.sender, mode, recordPacket);
      } catch {
        directory = null;
      }

      const outcome = await decryptAndVerify(
        email,
        imported!.encryptionPrivateKey,
        directory,
        recordCryptoStep,
      );
      const ok = outcome.payload !== null;
      const note =
        !ok && outcome.failedStage === "unwrap"
          ? "Unwrap failed — this message was encrypted to a different recipient's public key."
          : !ok && outcome.failedStage === "decrypt"
            ? "Unwrapped, but the AES-GCM tag failed — the ciphertext was altered."
            : undefined;

      recordIncident({
        category: "key-import",
        severity: ok ? "info" : "medium",
        title: ok
          ? "Message decrypted with imported third-party key"
          : "Imported key failed to decrypt message",
        detail: ok
          ? `The imported key “${imported!.label}” successfully unwrapped and decrypted this message; verification verdict: ${outcome.verification.status}.`
          : `The imported key “${imported!.label}” could not decrypt this message (${outcome.failedStage ?? "unknown"} stage). ${outcome.verification.reason}`,
        sender: email.sender,
        recipient: email.recipient,
        subject: email.subject,
        messageId: email.id,
        verdict: outcome.verification.status,
        meta: {
          importedLabel: imported!.label,
          importedFingerprint: imported!.fingerprint,
          failedStage: outcome.failedStage ?? "none",
        },
      });

      setResult({
        ok,
        verification: outcome.verification,
        body: outcome.payload?.body ?? null,
        note,
      });
    } catch (cause) {
      setResult({
        ok: false,
        note: cause instanceof Error ? cause.message : "Decryption attempt failed",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-lg border border-violet-500/30 bg-violet-500/5 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <KeyRound className="h-3.5 w-3.5 text-violet-300" />
        <span className="text-[11px] font-bold uppercase tracking-wider text-violet-300">
          Imported key: {imported.label}
        </span>
        <span className="font-mono text-[10px] text-violet-300/70">
          {imported.fingerprint.slice(0, 10)}…
        </span>
        <button
          onClick={() => void attemptDecrypt()}
          disabled={busy}
          className="ml-auto flex items-center gap-1.5 rounded-md border border-violet-500/40 px-2.5 py-1 text-[11px] font-semibold text-violet-200 transition-colors hover:bg-violet-500/15 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <KeyRound className="h-3 w-3" />}
          Try decrypting with imported key
        </button>
      </div>

      {result && (
        <div className="mt-2 space-y-1.5">
          <p className={result.ok ? "text-[11px] text-emerald-300" : "text-[11px] text-red-300"}>
            {result.ok
              ? `Decryption SUCCEEDED with the imported key (verdict: ${result.verification?.status}).`
              : "Decryption FAILED with the imported key."}
          </p>
          {result.note && <p className="text-[11px] text-slate-400">{result.note}</p>}
          {result.ok && result.body && (
            <pre className="max-h-40 overflow-auto rounded bg-slate-950 p-3 text-[11px] leading-relaxed break-all whitespace-pre-wrap text-violet-200/90">
              {result.body}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
