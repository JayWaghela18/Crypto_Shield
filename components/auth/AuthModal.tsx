"use client";

/**
 * Authentication command modal.
 *
 * Three paths into the lab:
 *  • Sign In  — accounts already stored on this device (private keys included)
 *               or a directory lookup for an address registered elsewhere.
 *  • Register — creates a REAL RSA-OAEP + RSA-PSS identity in this browser and
 *               publishes only the public halves to the key directory.
 *  • Demo     — one-click Alice / Bob / Bank Admin profiles for testing.
 *
 * `mode="gate"` renders the same panel as a blocking first-run screen with a
 * guest escape hatch; `mode="modal"` is the switch-account dialog.
 */

import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  ArrowRight,
  CheckCircle2,
  Fingerprint,
  KeyRound,
  Loader2,
  LockKeyhole,
  LogIn,
  Mail,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  UserPlus,
  X,
} from "lucide-react";
import type { DirectoryEntry, LocalAccount } from "@/lib/types";
import { DEMO_PROFILES, type DemoProfileId } from "@/lib/constants";
import { useAuth } from "@/store/AuthContext";

type Tab = "signin" | "register" | "demo";

interface AuthModalProps {
  open: boolean;
  mode?: "gate" | "modal";
  onClose?: () => void;
  initialTab?: Tab;
}

function shortFp(fp?: string): string {
  if (!fp) return "—";
  return `FP:${fp.slice(0, 4)}…${fp.slice(-4)}`;
}

const fieldLabel =
  "mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500";

export default function AuthModal({
  open,
  mode = "gate",
  onClose,
  initialTab = "signin",
}: AuthModalProps) {
  const {
    accounts,
    busy,
    error,
    clearError,
    signIn,
    register,
    quickDemo,
    guest,
    lookup,
    resetDeviceKeys,
  } = useAuth();

  const [tab, setTab] = useState<Tab>(initialTab);
  const [form, setForm] = useState({ name: "", email: "", role: "" });
  const [lookupEmail, setLookupEmail] = useState("");
  const [lookupState, setLookupState] = useState<
    { status: "idle" | "searching" } | { status: "found"; entry: DirectoryEntry } | { status: "missing" }
  >({ status: "idle" });
  const [localError, setLocalError] = useState<string | null>(null);
  const openedRef = useRef(false);

  // Reset transient state whenever the dialog (re)opens. On a first-run gate
  // with existing identities, land on Sign In instead of the demo tab.
  useEffect(() => {
    if (!open) {
      openedRef.current = false;
      return;
    }
    clearError();
    setLocalError(null);
    setLookupState({ status: "idle" });
    if (!openedRef.current) {
      openedRef.current = true;
      setTab(accounts.length > 0 && mode === "gate" ? "signin" : initialTab);
    }
  }, [open, clearError, accounts.length, mode, initialTab]);

  if (!open) return null;

  const message = localError ?? error;

  async function handleRegister(event: FormEvent) {
    event.preventDefault();
    setLocalError(null);
    const ok = await register(form);
    if (ok) {
      setForm({ name: "", email: "", role: "" });
      onClose?.();
    }
  }

  async function handleSignIn(email: string) {
    setLocalError(null);
    const ok = await signIn(email);
    if (ok) onClose?.();
  }

  async function handleLookup(event: FormEvent) {
    event.preventDefault();
    setLocalError(null);
    setLookupState({ status: "searching" });
    const entry = await lookup(lookupEmail);
    setLookupState(entry ? { status: "found", entry } : { status: "missing" });
  }

  async function handleDemo(id: DemoProfileId) {
    setLocalError(null);
    const ok = await quickDemo(id);
    if (ok) onClose?.();
  }

  async function handleGuest() {
    setLocalError(null);
    const ok = await guest();
    if (ok) onClose?.();
  }

  const tabs: { id: Tab; label: string; icon: typeof LogIn }[] = [
    { id: "signin", label: "Sign In", icon: LogIn },
    { id: "register", label: "Register", icon: UserPlus },
    { id: "demo", label: "Demo Access", icon: Sparkles },
  ];

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="CryptoShield authentication"
      className="fixed inset-0 z-[70] flex items-center justify-center overflow-y-auto p-3 sm:p-6"
    >
      <div
        className="absolute inset-0 bg-slate-950/85 backdrop-blur-md"
        onClick={mode === "modal" ? onClose : undefined}
      />

      <div className="relative my-auto grid w-full max-w-5xl animate-fadeup overflow-hidden rounded-2xl border border-slate-700/60 bg-slate-900/90 shadow-[0_40px_120px_-20px_rgba(0,0,0,0.9)] backdrop-blur-xl lg:grid-cols-[0.9fr_1.1fr]">
        {/* ── Brand panel ─────────────────────────────────────────── */}
        <aside className="relative hidden overflow-hidden border-r border-slate-800/80 bg-slate-950/70 p-8 lg:flex lg:flex-col">
          <div className="pointer-events-none absolute inset-0 bg-cyber-radial" />
          <div
            aria-hidden
            className="absolute -right-24 top-10 h-64 w-64 rounded-full border border-cyan-400/20"
          />
          <div
            aria-hidden
            className="absolute -right-14 top-24 h-44 w-44 animate-pulseglow rounded-full border border-emerald-400/20"
          />

          <div className="relative flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-400/10 ring-1 ring-cyan-400/40">
              <ShieldCheck className="h-5 w-5 text-cyan-300" />
            </span>
            <div className="leading-tight">
              <p className="text-sm font-black tracking-[0.18em] text-slate-100">
                CRYPTOSHIELD
              </p>
              <p className="text-[10px] uppercase tracking-[0.24em] text-cyan-300/60">
                Secure Mail Ops
              </p>
            </div>
          </div>

          <div className="relative mt-10">
            <p className="eyebrow">Zero trust identity</p>
            <h2 className="mt-2 text-2xl font-black leading-tight tracking-tight text-white">
              Your keys never
              <br />
              leave this browser.
            </h2>
            <p className="mt-3 max-w-xs text-xs leading-relaxed text-slate-400">
              Every account gets a real 2048-bit RSA-OAEP encryption pair and an
              RSA-PSS signing pair, generated locally with Web Crypto. The server
              only ever sees public keys and opaque envelopes.
            </p>
          </div>

          <ul className="relative mt-8 space-y-3 text-[11px] text-slate-300">
            {[
              "RSA-OAEP-256 key wrapping",
              "AES-256-GCM message payloads",
              "RSA-PSS signatures + CRL checks",
              "Directory-verified sender binding",
            ].map((item) => (
              <li key={item} className="flex items-center gap-2">
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
                {item}
              </li>
            ))}
          </ul>

          <div className="relative mt-auto flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-[10px] text-slate-500">
            <LockKeyhole className="h-3 w-3 text-emerald-400" />
            Private keys · localStorage · this device only
          </div>
        </aside>

        {/* ── Form panel ──────────────────────────────────────────── */}
        <section className="relative flex max-h-[88vh] flex-col">
          <header className="flex items-center justify-between gap-3 border-b border-slate-800/80 px-5 pt-5">
            <div className="flex flex-1 gap-1">
              {tabs.map(({ id, label, icon: Icon }) => {
                const active = tab === id;
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => {
                      setTab(id);
                      setLocalError(null);
                      clearError();
                    }}
                    className={[
                      "relative flex items-center gap-1.5 rounded-t-lg px-3 py-2 text-xs font-bold transition-colors",
                      active
                        ? "text-cyan-200"
                        : "text-slate-500 hover:text-slate-300",
                    ].join(" ")}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    {label}
                    {active && (
                      <span className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-cyan-400 shadow-glow" />
                    )}
                  </button>
                );
              })}
            </div>
            {mode === "modal" && (
              <button
                type="button"
                onClick={onClose}
                aria-label="Close"
                className="mb-2 rounded-lg border border-slate-800 p-1.5 text-slate-400 transition-colors hover:border-slate-600 hover:text-slate-200"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </header>

          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">
            {tab === "signin" && (
              <div className="animate-fadein space-y-5">
                <div>
                  <p className="eyebrow">Local vault</p>
                  <h3 className="mt-1 text-lg font-bold tracking-tight">
                    Accounts on this device
                  </h3>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    One click restores the session and its private keys.
                  </p>
                </div>

                {accounts.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-700/70 bg-slate-950/40 px-4 py-5 text-center">
                    <KeyRound className="mx-auto h-5 w-5 text-slate-600" />
                    <p className="mt-2 text-xs text-slate-400">
                      No identities on this device yet.
                    </p>
                    <button
                      type="button"
                      onClick={() => setTab("register")}
                      className="mt-2 text-xs font-semibold text-cyan-300 hover:text-cyan-200"
                    >
                      Generate your first key pair →
                    </button>
                  </div>
                ) : (
                  <ul className="space-y-2">
                    {accounts.map((entry: LocalAccount) => (
                      <li key={entry.email}>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void handleSignIn(entry.email)}
                          className="group flex w-full items-center gap-3 rounded-xl border border-slate-800 bg-slate-950/40 px-3 py-2.5 text-left transition-all hover:border-cyan-400/40 hover:bg-slate-900/70 hover:shadow-glow disabled:opacity-60"
                        >
                          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-800/80 text-base ring-1 ring-slate-700">
                            {entry.avatar}
                          </span>
                          <span className="min-w-0 flex-1">
                            <span className="flex items-center gap-2">
                              <span className="truncate text-sm font-semibold text-slate-100">
                                {entry.displayName}
                              </span>
                              <span className={`chip bg-slate-800 text-slate-400`}>
                                {entry.role}
                              </span>
                            </span>
                            <span className="mt-0.5 flex items-center gap-2">
                              <span className="truncate font-mono text-[10px] text-slate-500">
                                {entry.email}
                              </span>
                              <span className="key-badge">{shortFp(entry.fingerprint)}</span>
                            </span>
                          </span>
                          <ArrowRight className="h-4 w-4 shrink-0 text-slate-600 transition-transform group-hover:translate-x-0.5 group-hover:text-cyan-300" />
                        </button>
                      </li>
                    ))}
                  </ul>
                )}

                <div className="border-t border-slate-800/80 pt-4">
                  <p className="eyebrow">Directory lookup</p>
                  <p className="mt-1 text-[11px] text-slate-500">
                    Sign in with an address registered on another device.
                  </p>
                  <form onSubmit={handleLookup} className="mt-2 flex gap-2">
                    <div className="relative flex-1">
                      <Mail className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
                      <input
                        type="email"
                        value={lookupEmail}
                        onChange={(event) => setLookupEmail(event.target.value)}
                        placeholder="you@cryptoshield.dev"
                        className="input-cyber pl-8"
                        required
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={lookupState.status === "searching"}
                      className="btn-ghost"
                    >
                      {lookupState.status === "searching" ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Fingerprint className="h-3.5 w-3.5" />
                      )}
                      Lookup
                    </button>
                  </form>

                  {lookupState.status === "missing" && (
                    <p className="mt-2 flex items-center gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-300">
                      <TriangleAlert className="h-3.5 w-3.5" />
                      No such account in the directory. Register it below.
                    </p>
                  )}

                  {lookupState.status === "found" && (
                    <div className="mt-2 rounded-lg border border-cyan-400/25 bg-cyan-400/[0.06] px-3 py-2.5">
                      <p className="flex items-center gap-2 text-xs font-semibold text-cyan-200">
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        {lookupState.entry.name ?? lookupState.entry.address}
                      </p>
                      <p className="mt-0.5 font-mono text-[10px] text-cyan-300/60">
                        {lookupState.entry.address} · {shortFp(lookupState.entry.fingerprint)}
                      </p>
                      {accounts.some((entry) => entry.email === lookupState.entry.address) ? (
                        <button
                          type="button"
                          onClick={() => void handleSignIn(lookupState.entry.address)}
                          className="btn-primary mt-2 w-full"
                        >
                          <LogIn className="h-3.5 w-3.5" /> Sign in with local keys
                        </button>
                      ) : (
                        <>
                          <p className="mt-1.5 text-[10px] leading-relaxed text-slate-400">
                            This device holds no private key for that address. Generating a
                            new pair rotates the directory certificate; mail encrypted to
                            the old key becomes unreadable.
                          </p>
                          <button
                            type="button"
                            onClick={() =>
                              void resetDeviceKeys(
                                lookupState.entry.address,
                                lookupState.entry.name,
                              ).then((ok) => ok && onClose?.())
                            }
                            disabled={busy}
                            className="btn-primary mt-2 w-full"
                          >
                            {busy ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                              <KeyRound className="h-3.5 w-3.5" />
                            )}
                            Generate keys on this device
                          </button>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {tab === "register" && (
              <form onSubmit={handleRegister} className="animate-fadein space-y-4">
                <div>
                  <p className="eyebrow">New identity</p>
                  <h3 className="mt-1 text-lg font-bold tracking-tight">
                    Register an account
                  </h3>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Keys are generated locally — nothing secret is uploaded.
                  </p>
                </div>

                <div>
                  <label className={fieldLabel} htmlFor="reg-name">
                    Display name
                  </label>
                  <input
                    id="reg-name"
                    className="input-cyber"
                    value={form.name}
                    onChange={(event) => setForm({ ...form, name: event.target.value })}
                    placeholder="Jordan Vale"
                    autoComplete="name"
                    required
                  />
                </div>

                <div>
                  <label className={fieldLabel} htmlFor="reg-email">
                    Email address
                  </label>
                  <input
                    id="reg-email"
                    type="email"
                    className="input-cyber"
                    value={form.email}
                    onChange={(event) => setForm({ ...form, email: event.target.value })}
                    placeholder="jordan@cryptoshield.dev"
                    autoComplete="email"
                    required
                  />
                </div>

                <div>
                  <label className={fieldLabel} htmlFor="reg-role">
                    Role / title <span className="text-slate-600">(optional)</span>
                  </label>
                  <input
                    id="reg-role"
                    className="input-cyber"
                    value={form.role}
                    onChange={(event) => setForm({ ...form, role: event.target.value })}
                    placeholder="Security Analyst"
                  />
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2.5">
                  <p className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400">
                    <KeyRound className="h-3 w-3 text-cyan-300" />
                    What happens on submit
                  </p>
                  <ol className="mt-1.5 space-y-1 font-mono text-[10px] text-slate-500">
                    <li>01 · generate RSA-OAEP-2048 (encrypt) + RSA-PSS-2048 (sign)</li>
                    <li>02 · build X.509-style + PGP-style certificates</li>
                    <li>03 · publish PUBLIC keys to the directory</li>
                    <li>04 · seal private keys in this browser</li>
                  </ol>
                </div>

                <button type="submit" disabled={busy} className="btn-primary w-full">
                  {busy ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Generating RSA-2048 key material…
                    </>
                  ) : (
                    <>
                      <UserPlus className="h-4 w-4" />
                      Create identity
                    </>
                  )}
                </button>
              </form>
            )}

            {tab === "demo" && (
              <div className="animate-fadein space-y-4">
                <div>
                  <p className="eyebrow">Instant access</p>
                  <h3 className="mt-1 text-lg font-bold tracking-tight">
                    Quick demo profiles
                  </h3>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Each profile generates its own real key pair on first entry.
                  </p>
                </div>

                <ul className="space-y-2">
                  {DEMO_PROFILES.map((demo) => (
                    <li key={demo.id}>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void handleDemo(demo.id)}
                        className="group flex w-full items-center gap-3 rounded-xl border border-slate-800 bg-slate-950/40 px-3 py-3 text-left transition-all hover:border-emerald-400/40 hover:bg-slate-900/70 hover:shadow-glow-green disabled:opacity-60"
                      >
                        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-slate-800/80 text-lg ring-1 ring-slate-700">
                          {demo.avatar}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-2">
                            <span className="text-sm font-semibold text-slate-100">
                              {demo.name}
                            </span>
                            <span className="chip bg-emerald-500/10 text-emerald-300">
                              {demo.role}
                            </span>
                          </span>
                          <span className="mt-0.5 block truncate text-[10px] text-slate-500">
                            {demo.blurb}
                          </span>
                          <span className="mt-1 block font-mono text-[10px] text-slate-600">
                            {demo.email}
                          </span>
                        </span>
                        <ArrowRight className="h-4 w-4 shrink-0 text-slate-600 transition-transform group-hover:translate-x-0.5 group-hover:text-emerald-300" />
                      </button>
                    </li>
                  ))}
                </ul>

                <div className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2.5 text-[10px] leading-relaxed text-slate-500">
                  <b className="text-slate-300">Tip:</b> sign in as Bob to see mail
                  Alice sent you, then switch back to Alice and try the spoofing lab.
                  Each profile&apos;s private keys stay cached in this browser.
                </div>
              </div>
            )}

            {message && (
              <p className="mt-4 flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-[11px] leading-relaxed text-rose-300">
                <TriangleAlert className="mt-px h-3.5 w-3.5 shrink-0" />
                {message}
              </p>
            )}
          </div>

          <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800/80 px-5 py-3">
            <button
              type="button"
              onClick={() => void handleGuest()}
              disabled={busy}
              className="text-[11px] font-semibold text-slate-400 underline decoration-slate-700 underline-offset-4 transition-colors hover:text-cyan-300"
            >
              Skip auth — continue as guest
            </button>
            <span className="flex items-center gap-1.5 text-[10px] text-slate-600">
              <LockKeyhole className="h-3 w-3" />
              demo build · no server-side secrets
            </span>
          </footer>
        </section>
      </div>
    </div>
  );
}
