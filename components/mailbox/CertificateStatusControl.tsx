"use client";

/**
 * CRL simulation control — shown in the reading pane for secure messages while
 * Secure Mode is active. Revoking a sender's certificate does NOT invalidate
 * the signature: the RSA-PSS math still verifies, but the verification pipeline
 * must reject the message because the certificate is on the revocation list.
 */

import { useCallback, useEffect, useState } from "react";
import { Ban, Loader2, RefreshCw, ShieldCheck, ShieldOff } from "lucide-react";
import type { DirectoryEntry } from "@/lib/types";
import { fetchDirectoryKey, setCertificateRevocation } from "@/lib/api/emailClient";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useTransport } from "@/store/TransportContext";
import { useAudit } from "@/store/AuditContext";

function shortFp(fp?: string): string {
  if (!fp) return "—";
  return `${fp.slice(0, 10)}…${fp.slice(-6)}`;
}

export default function CertificateStatusControl({
  address,
  onChanged,
}: {
  address: string;
  /** Notify the mailbox so it can re-run verification. */
  onChanged: () => void;
}) {
  const { mode } = useSecurityMode();
  const { recordPacket } = useTransport();
  const { recordIncident } = useAudit();

  const [entry, setEntry] = useState<DirectoryEntry | null>(null);
  const [missing, setMissing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const fetched = await fetchDirectoryKey(address, mode, recordPacket);
      setEntry(fetched);
      setMissing(false);
    } catch {
      setEntry(null);
      setMissing(true);
    }
  }, [address, mode, recordPacket]);

  useEffect(() => {
    void load();
  }, [load]);

  async function toggle() {
    if (!entry) return;
    const revoking = !entry.revoked;
    setBusy(true);
    setError(null);
    try {
      const updated = await setCertificateRevocation(
        address,
        revoking,
        mode,
        recordPacket,
        revoking ? "keyCompromise (demo CRL)" : undefined,
      );
      setEntry(updated);
      recordIncident({
        category: "revoked-certificate",
        severity: revoking ? "high" : "info",
        title: revoking ? "Certificate revoked (CRL simulation)" : "Certificate reinstated",
        detail: revoking
          ? `The certificate for ${address} was added to the simulated CRL. The RSA-PSS signature still verifies, but S/MIME verification must now reject the message.`
          : `The certificate for ${address} was reinstated and is trusted again.`,
        sender: address,
        verdict: "revoked",
        meta: { address, revoked: revoking, reason: "keyCompromise (demo CRL)" },
      });
      onChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Revocation update failed");
    } finally {
      setBusy(false);
    }
  }

  if (missing) {
    return (
      <div className="rounded-lg border border-slate-700 bg-slate-900/60 px-4 py-2.5 text-[11px] text-slate-400">
        No published certificate for <b className="text-slate-300">{address}</b> — nothing to
        revoke.
      </div>
    );
  }

  const revoked = entry?.revoked === true;

  return (
    <div
      className={[
        "flex flex-wrap items-center gap-2 rounded-lg border px-4 py-2.5 text-[11px]",
        revoked
          ? "border-red-500/40 bg-red-500/10"
          : "border-slate-700 bg-slate-900/60",
      ].join(" ")}
    >
      <span className="flex items-center gap-1.5 font-bold uppercase tracking-wider text-slate-300">
        {revoked ? (
          <ShieldOff className="h-3.5 w-3.5 text-red-400" />
        ) : (
          <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
        )}
        CRL
      </span>

      <span className={revoked ? "text-red-300" : "text-emerald-300"}>
        {revoked ? "Certificate REVOKED" : "Certificate valid"}
      </span>

      <span className="font-mono text-slate-500">{shortFp(entry?.fingerprint)}</span>

      <div className="ml-auto flex items-center gap-2">
        {error && <span className="text-red-400">{error}</span>}
        <button
          onClick={() => void load()}
          disabled={busy}
          title="Refresh certificate status"
          className="rounded border border-slate-700 p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200 disabled:opacity-60"
        >
          <RefreshCw className="h-3 w-3" />
        </button>
        <button
          onClick={() => void toggle()}
          disabled={busy || !entry}
          className={[
            "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-60",
            revoked
              ? "border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10"
              : "border border-red-500/40 text-red-300 hover:bg-red-500/10",
          ].join(" ")}
        >
          {busy ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Ban className="h-3 w-3" />
          )}
          {revoked ? "Reinstate certificate" : "Revoke certificate"}
        </button>
      </div>
    </div>
  );
}
