"use client";

/**
 * Key Management panel — export this browser's RSA key pairs as JWK/PEM,
 * import external key material for third-party decryption testing, and inspect
 * the simulated Certificate Revocation List.
 *
 * ⚠ Private keys are exported ONLY when the user asks, and only to a local
 * download. The demo never transmits key material over the network.
 */

import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Download,
  KeyRound,
  Loader2,
  RefreshCw,
  Upload,
  X,
} from "lucide-react";
import type {
  ExportedKeyFile,
  KeyExportFormat,
  RevokedCertificate,
} from "@/lib/types";
import { useAuth } from "@/store/AuthContext";
import { useKeyVault } from "@/store/KeyVaultContext";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useTransport } from "@/store/TransportContext";
import { buildKeyFiles } from "@/lib/keys/bundle";
import { downloadFiles } from "@/lib/download";
import { fetchCrl } from "@/lib/api/emailClient";

function shortFp(fp?: string): string {
  if (!fp) return "—";
  return `${fp.slice(0, 10)}…${fp.slice(-6)}`;
}

const fieldClass =
  "w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500";

export default function KeyManager({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const { profile, status } = useAuth();
  const { imported, importMaterial, clearImported } = useKeyVault();
  const { mode } = useSecurityMode();
  const { recordPacket } = useTransport();

  const [format, setFormat] = useState<KeyExportFormat>("jwk");
  const [includePrivate, setIncludePrivate] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [exportNote, setExportNote] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  const [importText, setImportText] = useState("");
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importNote, setImportNote] = useState<string | null>(null);

  const [crl, setCrl] = useState<RevokedCertificate[]>([]);
  const [crlBusy, setCrlBusy] = useState(false);
  const [crlError, setCrlError] = useState<string | null>(null);

  const loadCrl = useCallback(async () => {
    setCrlBusy(true);
    setCrlError(null);
    try {
      setCrl(await fetchCrl(mode, recordPacket));
    } catch (cause) {
      setCrlError(cause instanceof Error ? cause.message : "CRL fetch failed");
    } finally {
      setCrlBusy(false);
    }
  }, [mode, recordPacket]);

  useEffect(() => {
    if (open) void loadCrl();
  }, [open, loadCrl]);

  // All hooks must run before this early return.
  if (!open) return null;

  async function handleExport() {
    if (!profile) return;
    setExporting(true);
    setExportNote(null);
    setExportError(null);
    try {
      const files: ExportedKeyFile[] = await buildKeyFiles(profile, format, includePrivate);
      downloadFiles(files);
      setExportNote(
        `Downloaded ${files.length} ${format.toUpperCase()} file(s)${
          includePrivate ? " — including private keys" : " (public keys only)"
        }.`,
      );
    } catch (cause) {
      setExportError(cause instanceof Error ? cause.message : "Export failed");
    } finally {
      setExporting(false);
    }
  }

  async function handleImport() {
    setImporting(true);
    setImportError(null);
    setImportNote(null);
    try {
      const identity = await importMaterial(importText, format);
      setImportNote(
        `Imported “${identity.label}” — key ${shortFp(identity.fingerprint)} (${identity.sourceFormat.toUpperCase()}).`,
      );
      setImportText("");
    } catch (cause) {
      setImportError(cause instanceof Error ? cause.message : "Import failed");
    } finally {
      setImporting(false);
    }
  }

  async function handleFile(file: File | undefined) {
    if (!file) return;
    setImportText(await file.text());
    setImportError(null);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-950/80 p-4 backdrop-blur-sm">
      <div className="my-6 w-full max-w-2xl rounded-xl border border-slate-700 bg-slate-900 shadow-2xl">
        {/* Header */}
        <div className="flex items-center gap-2 border-b border-slate-800 px-5 py-3">
          <KeyRound className="h-4 w-4 text-amber-400" />
          <h2 className="text-sm font-bold text-slate-100">Key Management</h2>
          {profile && (
            <span className="font-mono text-[11px] text-slate-500">
              {profile.email} · {shortFp(profile.certificate.x509.fingerprintSha256)}
            </span>
          )}
          <button
            onClick={onClose}
            aria-label="Close key management"
            className="ml-auto rounded-md border border-slate-700 p-1.5 text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-200"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>

        <div className="space-y-6 p-5">
          {/* ── EXPORT ─────────────────────────────────────────────── */}
          <section>
            <h3 className="mb-2 text-xs font-bold uppercase tracking-wider text-slate-400">
              1 · Export key pairs
            </h3>

            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-950 p-1">
                {(["jwk", "pem"] as KeyExportFormat[]).map((f) => (
                  <button
                    key={f}
                    onClick={() => setFormat(f)}
                    className={[
                      "rounded-md px-3 py-1 text-xs font-semibold uppercase transition-colors",
                      format === f
                        ? "bg-slate-700 text-white"
                        : "text-slate-400 hover:text-slate-200",
                    ].join(" ")}
                  >
                    {f}
                  </button>
                ))}
              </div>

              <label className="flex items-center gap-2 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={includePrivate}
                  onChange={(e) => setIncludePrivate(e.target.checked)}
                  className="h-3.5 w-3.5 accent-amber-500"
                />
                Include private keys
              </label>

              <button
                onClick={() => void handleExport()}
                disabled={!profile || status !== "ready" || exporting}
                className="ml-auto flex items-center gap-1.5 rounded-md bg-amber-600 px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-amber-500 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {exporting ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Download className="h-3.5 w-3.5" />
                )}
                Download key files
              </button>
            </div>

            {includePrivate && (
              <p className="mt-2 flex items-center gap-1.5 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-[11px] text-amber-400">
                <AlertTriangle className="h-3 w-3" />
                Private keys will be written to a local file in plaintext. This is a
                teaching lab — a real client should protect them with a passphrase/OS keystore.
              </p>
            )}
            {exportNote && (
              <p className="mt-2 flex items-center gap-1.5 text-[11px] text-emerald-400">
                <CheckCircle2 className="h-3 w-3" /> {exportNote}
              </p>
            )}
            {exportError && (
              <p className="mt-2 text-[11px] text-red-400">{exportError}</p>
            )}
          </section>

          {/* ── IMPORT ─────────────────────────────────────────────── */}
          <section>
            <h3 className="mb-2 text-xs font-bold uppercase tracking-wider text-slate-400">
              2 · Import external keys (third-party decryption)
            </h3>

            <textarea
              value={importText}
              onChange={(e) => setImportText(e.target.value)}
              placeholder={
                format === "pem"
                  ? "-----BEGIN PRIVATE KEY-----\n…PEM key material…\n-----END PRIVATE KEY-----"
                  : '{ "version": 1, "label": "…", "encryptionPrivate": { "kty": "RSA", … } }'
              }
              className={`${fieldClass} min-h-[110px] resize-y font-mono text-[11px]`}
            />

            <div className="mt-2 flex flex-wrap items-center gap-2">
              <label className="flex cursor-pointer items-center gap-1.5 rounded-md border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800">
                <Upload className="h-3.5 w-3.5" />
                Choose file
                <input
                  type="file"
                  accept=".json,.pem,.txt,.key"
                  className="hidden"
                  onChange={(e) => void handleFile(e.target.files?.[0])}
                />
              </label>

              <button
                onClick={() => void handleImport()}
                disabled={importing || !importText.trim()}
                className="flex items-center gap-1.5 rounded-md bg-slate-700 px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-slate-600 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {importing ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Upload className="h-3.5 w-3.5" />
                )}
                Import key
              </button>

              {imported && (
                <button
                  onClick={clearImported}
                  className="ml-auto rounded-md border border-red-500/40 px-3 py-1.5 text-xs font-semibold text-red-300 transition-colors hover:bg-red-500/10"
                >
                  Clear imported key
                </button>
              )}
            </div>

            <p className="mt-2 text-[11px] text-slate-500">
              JSON bundles and PEM are both accepted. PEM has no key-role metadata, so the
              first PRIVATE KEY block is treated as the decryption key.
            </p>
            {importNote && (
              <p className="mt-1 flex items-center gap-1.5 text-[11px] text-emerald-400">
                <CheckCircle2 className="h-3 w-3" /> {importNote}
              </p>
            )}
            {importError && <p className="mt-1 text-[11px] text-red-400">{importError}</p>}
            {imported && !importNote && (
              <p className="mt-1 font-mono text-[11px] text-slate-400">
                active: {imported.label} · {shortFp(imported.fingerprint)}
              </p>
            )}
          </section>

          {/* ── CRL ───────────────────────────────────────────────── */}
          <section>
            <h3 className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-400">
              3 · Certificate Revocation List (simulated)
              <button
                onClick={() => void loadCrl()}
                disabled={crlBusy}
                className="ml-auto flex items-center gap-1 rounded border border-slate-700 px-2 py-0.5 text-[10px] font-semibold normal-case text-slate-400 hover:bg-slate-800 hover:text-slate-200 disabled:opacity-60"
              >
                <RefreshCw className={`h-3 w-3 ${crlBusy ? "animate-spin" : ""}`} />
                Refresh
              </button>
            </h3>

            {crlError && <p className="text-[11px] text-red-400">{crlError}</p>}
            {!crlError && crl.length === 0 && (
              <p className="text-[11px] text-slate-500">
                No revoked certificates — revoke a sender from a secure message’s reading pane.
              </p>
            )}
            {crl.length > 0 && (
              <ul className="divide-y divide-slate-800 rounded-md border border-slate-800">
                {crl.map((entry) => (
                  <li
                    key={entry.address}
                    className="flex items-center gap-2 px-3 py-2 text-[11px]"
                  >
                    <Ban className="h-3.5 w-3.5 shrink-0 text-red-400" />
                    <span className="truncate text-slate-200">{entry.address}</span>
                    <span className="ml-auto shrink-0 font-mono text-slate-500">
                      {shortFp(entry.fingerprint)}
                    </span>
                    <span className="shrink-0 text-slate-500">{entry.revokeReason}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
