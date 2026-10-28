"use client";

/**
 * Operations overview — the command center landing page.
 *
 * Everything here reads live client state: the active identity, the published
 * directory, the crypto execution counters and the incident log. No database
 * round-trip is required, so the dashboard works offline.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Activity,
  ArrowRight,
  BadgeCheck,
  Ban,
  Bug,
  ChevronRight,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Mail,
  Network,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Sparkles,
  Terminal,
  UserRound,
  Zap,
} from "lucide-react";
import type { DirectoryEntry } from "@/lib/types";
import { fetchDirectoryList } from "@/lib/api/emailClient";
import { useAuth } from "@/store/AuthContext";
import { useAudit } from "@/store/AuditContext";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useTransport } from "@/store/TransportContext";

const ATTACKS = [
  {
    title: "MITM tampering",
    detail: "Flip one base64 character mid-flight. GCM auth fails in secure mode.",
    icon: Bug,
  },
  {
    title: "Stored XSS",
    detail: "Inject an onerror payload. DOMPurify strips it in secure mode.",
    icon: Siren,
  },
  {
    title: "Certificate spoofing",
    detail: "Claim a bank address. RSA-PSS + directory binding expose the forgery.",
    icon: Ban,
  },
];

function formatStamp(ts: number): string {
  const date = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

function shortFp(fp?: string): string {
  if (!fp) return "—";
  return `${fp.slice(0, 8)} … ${fp.slice(-8)}`;
}

const severityStyle: Record<string, string> = {
  critical: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-300",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  info: "border-cyan-400/30 bg-cyan-400/10 text-cyan-200",
};

export default function DashboardPage() {
  const { account, status, registered } = useAuth();
  const { mode, isSecure } = useSecurityMode();
  const { packets, cryptoSteps } = useTransport();
  const { incidents } = useAudit();
  const [directory, setDirectory] = useState<DirectoryEntry[]>([]);

  useEffect(() => {
    if (!account) return;
    let cancelled = false;
    fetchDirectoryList(mode)
      .then((entries) => {
        if (!cancelled) setDirectory(entries);
      })
      .catch(() => {
        if (!cancelled) setDirectory([]);
      });
    return () => {
      cancelled = true;
    };
  }, [account, mode]);

  if (status === "loading") {
    return (
      <div className="flex flex-1 items-center justify-center">
        <p className="animate-pulse font-mono text-xs text-slate-500">
          booting secure enclave…
        </p>
      </div>
    );
  }

  if (!account) {
    return (
      <div className="flex flex-1 items-center justify-center px-6">
        <div className="glass max-w-md rounded-2xl px-6 py-8 text-center">
          <LockKeyhole className="mx-auto h-6 w-6 text-cyan-300" />
          <h1 className="mt-3 text-lg font-bold">Session required</h1>
          <p className="mt-1 text-xs text-slate-500">
            Authenticate with a local key pair to open the command center.
          </p>
        </div>
      </div>
    );
  }

  const stats = [
    {
      label: "Directory nodes",
      value: directory.length,
      hint: "published RSA identities",
      icon: Network,
      tone: "text-cyan-300",
    },
    {
      label: "Wire packets",
      value: packets.length,
      hint: "captured this session",
      icon: Radar,
      tone: "text-sky-300",
    },
    {
      label: "Crypto ops",
      value: cryptoSteps.length,
      hint: "AES · RSA · SHA-256",
      icon: Zap,
      tone: "text-amber-300",
    },
    {
      label: "Incidents",
      value: incidents.length,
      hint: "detected + classified",
      icon: Siren,
      tone: "text-rose-300",
    },
  ];

  const posture = [
    {
      label: "Transport",
      value: isSecure ? "AES-256-GCM + RSA-OAEP" : "Plaintext JSON",
      ok: isSecure,
    },
    {
      label: "Sender integrity",
      value: isSecure ? "RSA-PSS · directory bound" : "Unverified From header",
      ok: isSecure,
    },
    {
      label: "Renderer",
      value: isSecure ? "DOMPurify sanitized" : "Raw HTML injection",
      ok: isSecure,
    },
    {
      label: "Directory publishing",
      value: registered ? "public keys live" : "pending…",
      ok: registered,
    },
  ];

  return (
    <div className="mx-auto w-full max-w-7xl space-y-5 px-4 py-6 sm:px-6 lg:px-8">
      {/* Hero */}
      <section className="cyber-edge glass relative overflow-hidden rounded-2xl px-5 py-5 sm:px-6">
        <div
          aria-hidden
          className="pointer-events-none absolute -right-16 -top-24 h-64 w-64 rounded-full bg-cyan-400/10 blur-3xl"
        />
        <div className="relative flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="eyebrow flex items-center gap-1.5">
              <Activity className="h-3 w-3" /> operations overview
            </p>
            <h1 className="mt-1.5 text-2xl font-black tracking-tight sm:text-3xl">
              Welcome back,{" "}
              <span className="text-glow text-cyan-200">
                {account.displayName.split(" ")[0]}
              </span>
            </h1>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="chip bg-cyan-400/10 text-cyan-200 ring-1 ring-cyan-400/20">
                <UserRound className="h-2.5 w-2.5" /> {account.role}
              </span>
              <span className="key-badge">
                <Fingerprint className="h-2.5 w-2.5" /> FP:{account.fingerprint.slice(0, 8)}
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
                {isSecure ? "E2EE active" : "vulnerability lab"}
              </span>
            </div>
          </div>

          <Link href="/mail" className="btn-primary">
            <Mail className="h-4 w-4" />
            Open secure mailbox
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>

        {/* Telemetry tiles */}
        <div className="relative mt-5 grid grid-cols-2 gap-2.5 lg:grid-cols-4">
          {stats.map(({ label, value, hint, icon: Icon, tone }) => (
            <div
              key={label}
              className="group rounded-xl border border-slate-800/80 bg-slate-950/50 px-3.5 py-3 transition-colors hover:border-slate-700"
            >
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-500">
                  {label}
                </p>
                <Icon className={`h-3.5 w-3.5 ${tone}`} />
              </div>
              <p className={`mt-1 font-mono text-2xl font-bold tabular-nums ${tone}`}>
                {value.toString().padStart(2, "0")}
              </p>
              <p className="text-[10px] text-slate-600">{hint}</p>
            </div>
          ))}
        </div>
      </section>

      <div className="grid gap-5 lg:grid-cols-[1.35fr_1fr]">
        {/* Identity dossier */}
        <section className="glass overflow-hidden rounded-2xl">
          <header className="flex items-center gap-2 border-b border-slate-800/80 px-5 py-3">
            <Fingerprint className="h-4 w-4 text-cyan-300" />
            <h2 className="text-sm font-bold">Identity dossier</h2>
            <span className="chip ml-auto bg-slate-800 text-slate-400">public material only</span>
          </header>

          <div className="space-y-4 px-5 py-4">
            <div className="flex items-center gap-3">
              <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-800 text-2xl ring-1 ring-slate-700">
                {account.avatar}
              </span>
              <div className="min-w-0">
                <p className="truncate text-base font-bold text-slate-100">
                  {account.displayName}
                </p>
                <p className="truncate font-mono text-[11px] text-slate-400">
                  {account.email}
                </p>
                <p className="mt-0.5 text-[10px] text-slate-600">
                  member since {new Date(account.createdAt).toISOString().slice(0, 10)} ·{" "}
                  {account.role}
                </p>
              </div>
            </div>

            <div>
              <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
                Signing key fingerprint · SHA-256
              </p>
              <p className="mt-1 break-all rounded-lg border border-cyan-400/15 bg-slate-950/80 px-3 py-2 font-mono text-[11px] leading-relaxed text-cyan-200/80">
                {shortFp(account.fingerprint)}
              </p>
            </div>

            <div className="grid gap-2 sm:grid-cols-2">
              {[
                { label: "Encryption", value: "RSA-OAEP-256 · 2048-bit", icon: KeyRound },
                { label: "Signing", value: "RSA-PSS-256 · 2048-bit", icon: BadgeCheck },
                { label: "Certificates", value: "X.509-style + PGP-style", icon: Sparkles },
                { label: "Private keys", value: "this browser · localStorage", icon: LockKeyhole },
              ].map(({ label, value, icon: Icon }) => (
                <div
                  key={label}
                  className="flex items-start gap-2 rounded-lg border border-slate-800/70 bg-slate-950/40 px-3 py-2"
                >
                  <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500" />
                  <div className="min-w-0">
                    <p className="text-[9px] font-bold uppercase tracking-wider text-slate-500">
                      {label}
                    </p>
                    <p className="truncate font-mono text-[11px] text-slate-300">{value}</p>
                  </div>
                </div>
              ))}
            </div>

            <p className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.05] px-3 py-2 text-[11px] leading-relaxed text-emerald-200/70">
              <ShieldCheck className="mr-1 inline h-3 w-3" />
              The server stores only the public half of this identity. Decryption always
              happens on this device, after the envelope is unwrapped with your RSA-OAEP
              private key.
            </p>
          </div>
        </section>

        {/* Posture + incidents */}
        <div className="space-y-5">
          <section className="glass overflow-hidden rounded-2xl">
            <header className="flex items-center gap-2 border-b border-slate-800/80 px-5 py-3">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <h2 className="text-sm font-bold">Security posture</h2>
              <span
                className={[
                  "chip ml-auto",
                  isSecure
                    ? "bg-emerald-500/10 text-emerald-300"
                    : "bg-rose-500/10 text-rose-300",
                ].join(" ")}
              >
                {mode} mode
              </span>
            </header>
            <ul className="divide-y divide-slate-800/70">
              {posture.map(({ label, value, ok }) => (
                <li key={label} className="flex items-center gap-3 px-5 py-2.5">
                  <span
                    className={[
                      "h-1.5 w-1.5 shrink-0 rounded-full",
                      ok ? "bg-emerald-400 shadow-glow-green" : "bg-rose-500 shadow-glow-red",
                    ].join(" ")}
                  />
                  <span className="text-[11px] font-semibold text-slate-400">{label}</span>
                  <span
                    className={[
                      "ml-auto text-right font-mono text-[10px]",
                      ok ? "text-slate-300" : "text-rose-300",
                    ].join(" ")}
                  >
                    {value}
                  </span>
                </li>
              ))}
            </ul>
          </section>

          <section className="glass overflow-hidden rounded-2xl">
            <header className="flex items-center gap-2 border-b border-slate-800/80 px-5 py-3">
              <Terminal className="h-4 w-4 text-amber-300" />
              <h2 className="text-sm font-bold">Incident feed</h2>
              <span className="ml-auto font-mono text-[10px] text-slate-600">
                {incidents.length} logged
              </span>
            </header>
            {incidents.length === 0 ? (
              <div className="px-5 py-6 text-center">
                <ShieldCheck className="mx-auto h-5 w-5 text-emerald-400/70" />
                <p className="mt-2 text-[11px] text-slate-500">
                  No incidents detected. Run an attack simulation from the mailbox.
                </p>
              </div>
            ) : (
              <ul className="max-h-56 divide-y divide-slate-800/70 overflow-y-auto">
                {[...incidents]
                  .reverse()
                  .slice(0, 5)
                  .map((incident) => (
                    <li key={incident.id} className="px-5 py-2.5">
                      <div className="flex items-center gap-2">
                        <span
                          className={`chip border ${severityStyle[incident.severity] ?? severityStyle.info}`}
                        >
                          {incident.severity}
                        </span>
                        <span className="text-[11px] font-semibold text-slate-200">
                          {incident.title}
                        </span>
                        <span className="ml-auto font-mono text-[9px] text-slate-600">
                          {formatStamp(incident.timestamp)}
                        </span>
                      </div>
                      <p className="mt-1 line-clamp-2 text-[10px] leading-relaxed text-slate-500">
                        {incident.detail}
                      </p>
                    </li>
                  ))}
              </ul>
            )}
          </section>
        </div>
      </div>

      {/* Attack surface */}
      <section className="grid gap-3 sm:grid-cols-3">
        {ATTACKS.map(({ title, detail, icon: Icon }) => (
          <div
            key={title}
            className="group rounded-xl border border-slate-800/80 bg-slate-900/40 px-4 py-3 transition-all hover:border-rose-500/30 hover:bg-rose-500/[0.04]"
          >
            <p className="flex items-center gap-2 text-xs font-bold text-slate-200">
              <Icon className="h-3.5 w-3.5 text-rose-400" />
              {title}
            </p>
            <p className="mt-1 text-[10px] leading-relaxed text-slate-500">{detail}</p>
          </div>
        ))}
      </section>

      <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-800/80 bg-slate-900/30 px-4 py-2.5">
        <p className="font-mono text-[10px] text-slate-500">
          {account.email} › command center
        </p>
        <Link
          href="/mail"
          className="flex items-center gap-1 text-[11px] font-semibold text-cyan-300 transition-colors hover:text-cyan-200"
        >
          Go to mailbox <ChevronRight className="h-3 w-3" />
        </Link>
      </div>
    </div>
  );
}
