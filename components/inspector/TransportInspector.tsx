"use client";

/**
 * Live Transport & Packet Inspector (right pane) — Phase 2 edition.
 *
 * TWO live views:
 *  1. CRYPTOGRAPHIC EXECUTION — numbered step-by-step timeline of every
 *     engine operation (AES key generation → AES payload encryption →
 *     RSA-OAEP key wrapping → SHA-256 hashing → RSA-PSS signing →
 *     verification → DOMPurify sanitization), with per-step timings.
 *  2. WIRE PACKETS — every HTTP message captured by the fetch wrapper:
 *     direction, method, path, status, byte size, mode, raw headers/body.
 */

import { useState } from "react";
import {
  ArrowDownLeft,
  ArrowUpRight,
  BadgeCheck,
  Bug,
  ChevronDown,
  ChevronRight,
  Hash,
  KeyRound,
  Lock,
  LockOpen,
  PenTool,
  Radio,
  Sparkles,
  Trash2,
  XCircle,
} from "lucide-react";
import type { CryptoPhase, CryptoStep, TransportPacket } from "@/lib/types";
import { useTransport } from "@/store/TransportContext";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useAudit } from "@/store/AuditContext";
import IncidentReportButton from "@/components/inspector/IncidentReportButton";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

function formatClock(ts: number): string {
  return (
    new Date(ts).toLocaleTimeString(undefined, { hour12: false }) +
    "." +
    String(new Date(ts).getMilliseconds()).padStart(3, "0")
  );
}

/* ------------------------------------------------------------------ */
/* Crypto execution timeline                                           */
/* ------------------------------------------------------------------ */

const PHASE_META: Record<
  CryptoPhase,
  { icon: typeof Hash; label: string; className: string }
> = {
  keygen: { icon: KeyRound, label: "KEYGEN", className: "text-amber-400 bg-amber-500/10" },
  encrypt: { icon: Lock, label: "ENCRYPT", className: "text-blue-400 bg-blue-500/10" },
  decrypt: { icon: LockOpen, label: "DECRYPT", className: "text-violet-400 bg-violet-500/10" },
  hash: { icon: Hash, label: "HASH", className: "text-slate-300 bg-slate-500/10" },
  sign: { icon: PenTool, label: "SIGN", className: "text-sky-400 bg-sky-500/10" },
  verify: { icon: BadgeCheck, label: "VERIFY", className: "text-emerald-400 bg-emerald-500/10" },
  sanitize: { icon: Sparkles, label: "SANITIZE", className: "text-teal-400 bg-teal-500/10" },
  mitm: { icon: Bug, label: "ATTACK", className: "text-red-400 bg-red-500/20" },
};

function CryptoStepRow({ index, step }: { index: number; step: CryptoStep }) {
  const meta = PHASE_META[step.phase];
  const Icon = meta.icon;
  const failed = step.status === "fail";

  return (
    <li className="flex items-start gap-2.5 px-3 py-1.5 hover:bg-slate-900/60">
      <span className="mt-0.5 w-5 shrink-0 text-right font-mono text-[10px] text-slate-600">
        {index}
      </span>
      <span
        className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded ${meta.className}`}
      >
        {failed ? (
          <XCircle className="h-3 w-3 text-red-400" />
        ) : (
          <Icon className="h-3 w-3" />
        )}
      </span>
      <div className="min-w-0 flex-1">
        <p className={`text-xs font-semibold ${failed ? "text-red-400" : "text-slate-200"}`}>
          {step.label}
        </p>
        <p className="break-all font-mono text-[10px] leading-relaxed text-slate-500">
          {step.detail}
        </p>
      </div>
      <span className="shrink-0 font-mono text-[10px] tabular-nums text-slate-600">
        {step.durationMs < 1 ? "<1" : step.durationMs.toFixed(1)} ms
      </span>
    </li>
  );
}

function CryptoTimeline({ steps }: { steps: CryptoStep[] }) {
  if (steps.length === 0) return null;

  return (
    <div className="border-b border-slate-800 bg-slate-950/60">
      <p className="flex items-center gap-2 px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-400">
        <KeyRound className="h-3.5 w-3.5 text-amber-400" />
        Cryptographic execution — step by step
        <span className="ml-auto font-mono font-normal text-slate-600">
          {steps.length} steps
        </span>
      </p>
      <ul className="max-h-56 overflow-y-auto border-t border-slate-800/70">
        {steps.map((step, i) => (
          <CryptoStepRow key={step.id} index={i + 1} step={step} />
        ))}
      </ul>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Wire packet row                                                     */
/* ------------------------------------------------------------------ */

function PacketRow({ packet }: { packet: TransportPacket }) {
  const [open, setOpen] = useState(false);

  const outbound = packet.direction === "outbound";
  const statusColor =
    packet.status === undefined
      ? "text-slate-400"
      : packet.status < 300
        ? "text-emerald-400"
        : "text-red-400";

  return (
    <li className="border-b border-slate-800/70">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-slate-900"
      >
        {open ? (
          <ChevronDown className="h-3.5 w-3.5 shrink-0 text-slate-500" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-slate-500" />
        )}

        {outbound ? (
          <ArrowUpRight className="h-4 w-4 shrink-0 text-blue-400" />
        ) : (
          <ArrowDownLeft className="h-4 w-4 shrink-0 text-emerald-400" />
        )}

        <span
          className={[
            "w-14 shrink-0 rounded px-1.5 py-0.5 text-center text-[10px] font-bold",
            outbound ? "bg-blue-500/10 text-blue-400" : "bg-emerald-500/10 text-emerald-400",
          ].join(" ")}
        >
          {packet.method}
        </span>

        <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-300">
          {packet.url}
        </span>

        {packet.status !== undefined && (
          <span className={`text-xs font-bold ${statusColor}`}>{packet.status}</span>
        )}

        <span className="shrink-0 text-[11px] text-slate-500">
          {formatBytes(packet.sizeBytes)}
        </span>

        <span
          className={[
            "shrink-0 rounded px-1 py-0.5 text-[10px] font-bold uppercase",
            packet.mode === "secure"
              ? "bg-emerald-500/10 text-emerald-400"
              : "bg-red-500/10 text-red-400",
          ].join(" ")}
        >
          {packet.mode}
        </span>

        <span className="shrink-0 text-[11px] tabular-nums text-slate-600">
          {formatClock(packet.timestamp)}
        </span>
      </button>

      {open && (
        <div className="border-t border-slate-800/70 bg-slate-950/80 px-4 py-3">
          <p className="mb-1 text-[10px] font-bold uppercase tracking-wider text-slate-500">
            Headers
          </p>
          <pre className="mb-3 overflow-x-auto text-[11px] leading-relaxed text-slate-400">
            {`${packet.direction === "outbound" ? ">" : "<"} ${packet.method} ${packet.url}${
              packet.status !== undefined ? ` — ${packet.status}` : ""
            }\n` +
              Object.entries(packet.headers)
                .map(([k, v]) => `${k}: ${v}`)
                .join("\n")}
          </pre>

          <p className="mb-1 text-[10px] font-bold uppercase tracking-wider text-slate-500">
            Body — {formatBytes(packet.sizeBytes)} on the wire
          </p>
          <pre className="max-h-64 overflow-auto rounded bg-slate-950 p-3 text-[11px] leading-relaxed break-all whitespace-pre-wrap text-emerald-300/90">
            {packet.body || "(empty)"}
          </pre>
        </div>
      )}
    </li>
  );
}

/* ------------------------------------------------------------------ */
/* Panel                                                               */
/* ------------------------------------------------------------------ */

export default function TransportInspector() {
  const { packets, cryptoSteps, clearPackets } = useTransport();
  const { mode } = useSecurityMode();
  const { incidents } = useAudit();

  const outboundCount = packets.filter((p) => p.direction === "outbound").length;

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/50 px-4 py-3">
        <div className="flex items-center gap-2">
          <Radio className="h-4 w-4 animate-pulse text-emerald-400" />
          <div>
            <h2 className="text-sm font-bold text-slate-100">
              Live Transport &amp; Packet Inspector
            </h2>
            <p className="text-[11px] text-slate-500">
              {packets.length} packets · {cryptoSteps.length} crypto steps ·{" "}
              {outboundCount} sent · {incidents.length} incident
              {incidents.length === 1 ? "" : "s"} · wire is{" "}
              <span className={mode === "secure" ? "text-emerald-400" : "text-red-400"}>
                {mode === "secure" ? "encrypted (secure)" : "PLAINTEXT (unsafe)"}
              </span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <IncidentReportButton />
          <button
            onClick={clearPackets}
            className="flex items-center gap-1.5 rounded-md border border-slate-700 px-2.5 py-1.5 text-xs text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-200"
          >
            <Trash2 className="h-3.5 w-3.5" /> Clear
          </button>
        </div>
      </div>

      {/* Phase 2: step-by-step crypto execution */}
      <CryptoTimeline steps={cryptoSteps} />

      {/* Packet list */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {packets.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 p-8 text-center text-slate-500">
            <Radio className="h-8 w-8 text-slate-700" />
            <p className="text-sm">No traffic captured yet.</p>
            <p className="text-xs text-slate-600">
              Load a folder or send a message — every request/response and crypto
              operation appears here instantly.
            </p>
          </div>
        ) : (
          <ul>
            {packets.map((packet) => (
              <PacketRow key={packet.id} packet={packet} />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
