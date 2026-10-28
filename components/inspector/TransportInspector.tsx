"use client";

/**
 * Live transport + crypto inspector (right pane).
 *
 * Three feeds, one terminal:
 *   • CRYPTO — numbered log of every engine operation with timings
 *   • WIRE   — every HTTP request/response captured by the fetch wrapper
 *   • ALERTS — incidents classified by the audit pipeline
 */

import { useState } from "react";
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  BadgeCheck,
  Bug,
  ChevronDown,
  ChevronRight,
  Copy,
  Hash,
  KeyRound,
  Lock,
  LockOpen,
  PenTool,
  Radio,
  ShieldAlert,
  Sparkles,
  Terminal,
  Trash2,
  XCircle,
} from "lucide-react";
import type { CryptoPhase, CryptoStep, TransportPacket } from "@/lib/types";
import { useTransport } from "@/store/TransportContext";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useAudit } from "@/store/AuditContext";
import IncidentReportButton from "@/components/inspector/IncidentReportButton";

function formatBytes(n: number): string {
  return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`;
}

function clock(ts: number): string {
  const date = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(
    date.getSeconds(),
  )}.${String(date.getMilliseconds()).padStart(3, "0")}`;
}

const PHASE_META: Record<
  CryptoPhase,
  { icon: typeof Hash; label: string; className: string }
> = {
  keygen: { icon: KeyRound, label: "KEYGEN", className: "text-amber-300 bg-amber-500/10" },
  encrypt: { icon: Lock, label: "ENCRYPT", className: "text-cyan-300 bg-cyan-400/10" },
  decrypt: { icon: LockOpen, label: "DECRYPT", className: "text-violet-300 bg-violet-500/10" },
  hash: { icon: Hash, label: "HASH", className: "text-slate-300 bg-slate-500/10" },
  sign: { icon: PenTool, label: "SIGN", className: "text-sky-300 bg-sky-500/10" },
  verify: { icon: BadgeCheck, label: "VERIFY", className: "text-emerald-300 bg-emerald-500/10" },
  sanitize: { icon: Sparkles, label: "SANITIZE", className: "text-teal-300 bg-teal-500/10" },
  mitm: { icon: Bug, label: "ATTACK", className: "text-rose-300 bg-rose-500/15" },
};

function CryptoLine({ index, step }: { index: number; step: CryptoStep }) {
  const meta = PHASE_META[step.phase];
  const Icon = meta.icon;
  const failed = step.status === "fail";

  return (
    <li className="group flex items-start gap-2 px-3 py-1.5 transition-colors hover:bg-slate-900/70">
      <span className="w-4 shrink-0 pt-0.5 text-right font-mono text-[9px] text-slate-700">
        {index}
      </span>
      <span className="shrink-0 pt-0.5 font-mono text-[9px] text-slate-600">
        {clock(step.timestamp)}
      </span>
      <span
        className={`flex h-4 w-4 shrink-0 items-center justify-center rounded ${meta.className}`}
      >
        {failed ? <XCircle className="h-2.5 w-2.5 text-rose-400" /> : <Icon className="h-2.5 w-2.5" />}
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex items-baseline gap-1.5">
          <span
            className={`font-mono text-[9px] font-black uppercase tracking-wider ${
              failed ? "text-rose-400" : "text-slate-500"
            }`}
          >
            {meta.label}
          </span>
          <span
            className={`truncate text-[11px] font-semibold ${
              failed ? "text-rose-300" : "text-slate-200"
            }`}
          >
            {step.label}
          </span>
        </span>
        <span className="block truncate font-mono text-[9.5px] text-slate-600 group-hover:whitespace-normal group-hover:break-all">
          {step.detail}
        </span>
      </span>
      <span className="shrink-0 pt-0.5 font-mono text-[9px] tabular-nums text-slate-700">
        {step.durationMs < 1 ? "<1" : step.durationMs.toFixed(1)}ms
      </span>
    </li>
  );
}

function PacketRow({ packet }: { packet: TransportPacket }) {
  const [open, setOpen] = useState(false);
  const outbound = packet.direction === "outbound";
  const statusColor =
    packet.status === undefined
      ? "text-slate-500"
      : packet.status < 300
        ? "text-emerald-400"
        : "text-rose-400";
  const secure = packet.mode === "secure";

  return (
    <li className="border-b border-slate-800/50">
      <button
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-start gap-2 px-3 py-2 text-left transition-colors hover:bg-slate-900/70"
      >
        {open ? (
          <ChevronDown className="mt-0.5 h-3 w-3 shrink-0 text-slate-600" />
        ) : (
          <ChevronRight className="mt-0.5 h-3 w-3 shrink-0 text-slate-600" />
        )}
        <span className="shrink-0 pt-0.5 font-mono text-[9px] text-slate-600">
          {clock(packet.timestamp)}
        </span>
        {outbound ? (
          <ArrowUpRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-400" />
        ) : (
          <ArrowDownLeft className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
        )}
        <span
          className={[
            "mt-0.5 w-11 shrink-0 rounded px-1 py-0.5 text-center font-mono text-[9px] font-bold",
            outbound
              ? "bg-cyan-400/10 text-cyan-300"
              : "bg-emerald-500/10 text-emerald-300",
          ].join(" ")}
        >
          {packet.method}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate font-mono text-[10.5px] text-slate-300">
            {packet.url}
          </span>
          <span className="mt-0.5 flex items-center gap-2 font-mono text-[9px] text-slate-600">
            <span>{formatBytes(packet.sizeBytes)}</span>
            <span className={secure ? "text-emerald-400/80" : "text-rose-400/80"}>
              {secure ? "ciphertext" : "plaintext"}
            </span>
            {!outbound && packet.status !== undefined && (
              <span className={statusColor}>{packet.status}</span>
            )}
          </span>
        </span>
        {!outbound && packet.status !== undefined && (
          <span className={`shrink-0 font-mono text-[10px] font-bold ${statusColor}`}>
            {packet.status}
          </span>
        )}
      </button>

      {open && (
        <div className="border-t border-slate-800/50 bg-slate-950/80 px-3 py-2">
          <p className="mb-1 font-mono text-[9px] uppercase tracking-wider text-slate-600">
            headers
          </p>
          <pre className="mb-2 overflow-x-auto font-mono text-[10px] leading-relaxed text-slate-400">
            {`${outbound ? ">" : "<"} ${packet.method} ${packet.url}${
              packet.status !== undefined ? ` — ${packet.status}` : ""
            }\n` +
              Object.entries(packet.headers)
                .map(([key, value]) => `${key}: ${value}`)
                .join("\n")}
          </pre>
          <p className="mb-1 font-mono text-[9px] uppercase tracking-wider text-slate-600">
            body · {formatBytes(packet.sizeBytes)}
          </p>
          <pre className="max-h-56 overflow-auto break-all whitespace-pre-wrap rounded border border-slate-800/70 bg-slate-950 p-2.5 font-mono text-[10px] leading-relaxed text-emerald-300/80">
            {packet.body || "(empty)"}
          </pre>
        </div>
      )}
    </li>
  );
}

type Feed = "crypto" | "wire" | "alerts";

export default function TransportInspector() {
  const { packets, cryptoSteps, clearPackets } = useTransport();
  const { mode } = useSecurityMode();
  const { incidents, clearIncidents } = useAudit();
  const [feed, setFeed] = useState<Feed>("crypto");

  const outboundCount = packets.filter((packet) => packet.direction === "outbound").length;

  const feeds: { id: Feed; label: string; count: number; icon: typeof Hash }[] = [
    { id: "crypto", label: "crypto", count: cryptoSteps.length, icon: KeyRound },
    { id: "wire", label: "wire", count: packets.length, icon: Radio },
    { id: "alerts", label: "alerts", count: incidents.length, icon: ShieldAlert },
  ];

  return (
    <div className="flex h-full min-h-0 flex-col bg-slate-950/60">
      {/* Terminal header */}
      <div className="shrink-0 border-b border-slate-800/80 bg-slate-950/80 px-3 py-2.5">
        <div className="flex items-center gap-2">
          <span className="flex gap-1">
            <span className="h-2 w-2 rounded-full bg-rose-500/80" />
            <span className="h-2 w-2 rounded-full bg-amber-500/70" />
            <span className="h-2 w-2 rounded-full bg-emerald-500/80" />
          </span>
          <Terminal className="ml-1 h-3.5 w-3.5 text-emerald-400" />
          <h2 className="font-mono text-[11px] font-bold uppercase tracking-wider text-slate-200">
            transport.inspector
          </h2>
          <span className="ml-auto flex items-center gap-1 font-mono text-[9px] text-emerald-400">
            <span className="h-1.5 w-1.5 animate-pulseglow rounded-full bg-emerald-400" />
            live
          </span>
        </div>

        <div className="mt-1.5 flex flex-wrap items-center gap-2 font-mono text-[9px] text-slate-600">
          <span>{packets.length} packets</span>
          <span className="text-slate-800">/</span>
          <span>{outboundCount} out</span>
          <span className="text-slate-800">/</span>
          <span>{cryptoSteps.length} ops</span>
          <span className="text-slate-800">/</span>
          <span className={incidents.length > 0 ? "text-rose-400" : ""}>
            {incidents.length} alerts
          </span>
          <span
            className={[
              "ml-auto rounded px-1.5 py-0.5 font-bold uppercase tracking-wider",
              mode === "secure"
                ? "bg-emerald-500/10 text-emerald-300"
                : "bg-rose-500/10 text-rose-300",
            ].join(" ")}
          >
            {mode === "secure" ? "e2ee channel" : "plaintext channel"}
          </span>
        </div>

        <div className="mt-2 flex items-center gap-1">
          {feeds.map(({ id, label, count, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setFeed(id)}
              className={[
                "flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-wider transition-all",
                feed === id
                  ? "border-cyan-400/40 bg-cyan-400/10 text-cyan-200"
                  : "border-transparent text-slate-600 hover:border-slate-800 hover:text-slate-300",
              ].join(" ")}
            >
              <Icon className="h-2.5 w-2.5" />
              {label}
              <span className="text-slate-600">{count}</span>
            </button>
          ))}

          <div className="ml-auto flex items-center gap-1">
            <IncidentReportButton />
            <button
              onClick={() => {
                clearPackets();
                clearIncidents();
              }}
              title="Clear all feeds"
              className="flex items-center gap-1 rounded-md border border-slate-800 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider text-slate-500 transition-colors hover:border-slate-700 hover:text-slate-200"
            >
              <Trash2 className="h-2.5 w-2.5" />
              clear
            </button>
          </div>
        </div>
      </div>

      {/* Feeds */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {feed === "crypto" && (
          <>
            {cryptoSteps.length === 0 ? (
              <EmptyState
                icon={<Activity className="h-6 w-6 text-slate-700" />}
                title="awaiting crypto operations"
                hint="Send or open a secure message to stream AES/RSA steps here."
              />
            ) : (
              <ul className="divide-y divide-slate-800/40">
                {cryptoSteps.map((step, index) => (
                  <CryptoLine key={step.id} index={index + 1} step={step} />
                ))}
              </ul>
            )}
          </>
        )}

        {feed === "wire" && (
          <>
            {packets.length === 0 ? (
              <EmptyState
                icon={<Radio className="h-6 w-6 text-slate-700" />}
                title="no traffic captured"
                hint="Load a folder or send a message to stream packets here."
              />
            ) : (
              <ul>
                {packets.map((packet) => (
                  <PacketRow key={packet.id} packet={packet} />
                ))}
              </ul>
            )}
          </>
        )}

        {feed === "alerts" && (
          <>
            {incidents.length === 0 ? (
              <EmptyState
                icon={<BadgeCheck className="h-6 w-6 text-emerald-500/50" />}
                title="no incidents detected"
                hint="Run an attack simulation from the mailbox."
              />
            ) : (
              <ul className="divide-y divide-slate-800/40">
                {[...incidents].reverse().map((incident) => (
                  <li key={incident.id} className="px-3 py-2">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={[
                          "rounded px-1 py-0.5 font-mono text-[8.5px] font-black uppercase tracking-wider",
                          incident.severity === "critical"
                            ? "bg-rose-500/15 text-rose-300"
                            : incident.severity === "high"
                              ? "bg-orange-500/15 text-orange-300"
                              : incident.severity === "medium"
                                ? "bg-amber-500/15 text-amber-300"
                                : "bg-cyan-400/10 text-cyan-300",
                        ].join(" ")}
                      >
                        {incident.severity}
                      </span>
                      <span className="truncate text-[10.5px] font-semibold text-slate-200">
                        {incident.title}
                      </span>
                      <span className="ml-auto shrink-0 font-mono text-[8.5px] text-slate-600">
                        {clock(incident.timestamp)}
                      </span>
                    </div>
                    <p className="mt-1 text-[10px] leading-relaxed text-slate-500">
                      {incident.detail}
                    </p>
                    <p className="mt-1 font-mono text-[9px] text-slate-700">
                      {incident.category}
                      {incident.verdict ? ` · ${incident.verdict}` : ""}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </div>

      <footer className="flex shrink-0 items-center justify-between gap-2 border-t border-slate-800/80 bg-slate-950/80 px-3 py-1.5 font-mono text-[9px] text-slate-700">
        <span className="flex items-center gap-1">
          <Copy className="h-2.5 w-2.5" /> captured client-side
        </span>
        <span>sha-256 · aes-256-gcm · rsa-2048</span>
      </footer>
    </div>
  );
}

function EmptyState({
  icon,
  title,
  hint,
}: {
  icon: React.ReactNode;
  title: string;
  hint: string;
}) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-1.5 p-8 text-center">
      {icon}
      <p className="font-mono text-[11px] uppercase tracking-wider text-slate-500">{title}</p>
      <p className="max-w-[16rem] text-[10px] leading-relaxed text-slate-700">{hint}</p>
    </div>
  );
}
