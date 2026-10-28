"use client";

/**
 * Global command bar.
 *
 *  • Brand + section navigation (Overview / Mailbox)
 *  • Animated security-mode badge (unsafe ↔ E2EE)
 *  • Key-management drawer
 *  • Live identity pill: avatar, name, role, online pulse and signing-key
 *    fingerprint, with a dropdown to switch accounts, rotate keys or sign out.
 *
 * When no account is active the bar mounts the authentication gate.
 */

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ChevronDown,
  Gauge,
  KeyRound,
  LogIn,
  LogOut,
  Mail,
  Settings,
  ShieldCheck,
  UserRound,
  Wifi,
} from "lucide-react";
import SecurityModeToggle from "@/components/SecurityModeToggle";
import KeyManager from "@/components/keys/KeyManager";
import AuthModal from "@/components/auth/AuthModal";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useAuth } from "@/store/AuthContext";

const NAV_ITEMS = [
  { href: "/", label: "Overview", icon: Gauge },
  { href: "/mail", label: "Mailbox", icon: Mail },
] as const;

function shortFp(fp?: string): string {
  if (!fp) return "—";
  return `FP:${fp.slice(0, 4)}…${fp.slice(-4)}`;
}

export default function Navbar() {
  const pathname = usePathname();
  const { mode } = useSecurityMode();
  const { status, account, accounts, signIn, signOut } = useAuth();

  const [keysOpen, setKeysOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [authOpen, setAuthOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);

  const isSecure = mode === "secure";

  // Close the account dropdown on outside click / Escape.
  useEffect(() => {
    if (!menuOpen) return;
    function onPointerDown(event: MouseEvent) {
      if (!menuRef.current?.contains(event.target as Node)) setMenuOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setMenuOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [menuOpen]);

  const gateOpen = status === "signedOut" && !account;

  return (
    <>
      <header className="sticky top-0 z-40 flex h-16 shrink-0 items-center gap-3 border-b border-slate-800/80 bg-slate-950/80 px-3 backdrop-blur-xl sm:px-5">
        {/* Brand */}
        <Link href="/" className="group flex shrink-0 items-center gap-2.5">
          <span className="relative flex h-9 w-9 items-center justify-center rounded-xl border border-cyan-400/30 bg-cyan-400/[0.08] transition-shadow group-hover:shadow-glow">
            <ShieldCheck className="h-5 w-5 text-cyan-300" />
            <span
              aria-hidden
              className={[
                "absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full ring-2 ring-slate-950",
                isSecure ? "bg-emerald-400" : "bg-rose-500",
                "animate-pulseglow",
              ].join(" ")}
            />
          </span>
          <span className="hidden leading-tight sm:block">
            <span className="block text-sm font-black tracking-[0.16em] text-slate-100">
              CRYPTOSHIELD
            </span>
            <span className="block text-[9px] uppercase tracking-[0.26em] text-cyan-300/50">
              Secure mail ops
            </span>
          </span>
        </Link>

        {/* Section nav */}
        <nav className="ml-1 hidden items-center gap-0.5 md:flex">
          {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
            const active = pathname === href;
            return (
              <Link
                key={href}
                href={href}
                className={[
                  "relative flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors",
                  active
                    ? "text-cyan-200"
                    : "text-slate-500 hover:bg-slate-900 hover:text-slate-200",
                ].join(" ")}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
                {active && (
                  <span className="absolute inset-x-2 -bottom-[13px] h-0.5 rounded-full bg-cyan-400 shadow-glow" />
                )}
              </Link>
            );
          })}
        </nav>

        <div className="ml-auto flex items-center gap-2">
          {/* Mode badge */}
          <SecurityModeToggle />

          {/* Key management */}
          <button
            onClick={() => setKeysOpen(true)}
            title="Key management — export, import, CRL"
            className="hidden items-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-900/60 px-2.5 py-1.5 text-[11px] font-semibold text-slate-300 transition-all hover:border-cyan-400/40 hover:text-cyan-200 sm:flex"
          >
            <Settings className="h-3.5 w-3.5" />
            Keys
          </button>

          {/* Account pill / dropdown */}
          {account ? (
            <div ref={menuRef} className="relative">
              <button
                onClick={() => setMenuOpen((open) => !open)}
                aria-haspopup="menu"
                aria-expanded={menuOpen}
                className={[
                  "flex items-center gap-2 rounded-xl border px-2 py-1.5 text-left transition-all",
                  menuOpen
                    ? "border-cyan-400/40 bg-slate-900 shadow-glow"
                    : "border-slate-800 bg-slate-900/60 hover:border-slate-700",
                ].join(" ")}
              >
                <span className="relative flex h-7 w-7 items-center justify-center rounded-lg bg-slate-800 text-sm ring-1 ring-slate-700">
                  {account.avatar}
                  <span className="absolute -bottom-0.5 -right-0.5 h-2 w-2 rounded-full bg-emerald-400 ring-2 ring-slate-900" />
                </span>
                <span className="hidden min-w-0 leading-tight sm:block">
                  <span className="block max-w-[9rem] truncate text-xs font-bold text-slate-100">
                    {account.displayName}
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="hidden max-w-[7rem] truncate font-mono text-[9px] text-slate-500 lg:block">
                      {account.email}
                    </span>
                    <span className="key-badge">{shortFp(account.fingerprint)}</span>
                  </span>
                </span>
                <ChevronDown
                  className={[
                    "h-3.5 w-3.5 shrink-0 text-slate-500 transition-transform",
                    menuOpen ? "rotate-180" : "",
                  ].join(" ")}
                />
              </button>

              {menuOpen && (
                <div
                  role="menu"
                  className="absolute right-0 top-[calc(100%+8px)] w-80 animate-fadeup overflow-hidden rounded-xl border border-slate-700/70 bg-slate-900/95 shadow-2xl backdrop-blur-xl"
                >
                  <div className="border-b border-slate-800/80 bg-slate-950/60 px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-800 text-base ring-1 ring-slate-700">
                        {account.avatar}
                      </span>
                      <div className="min-w-0">
                        <p className="truncate text-sm font-bold text-slate-100">
                          {account.displayName}
                        </p>
                        <p className="truncate font-mono text-[10px] text-slate-500">
                          {account.email}
                        </p>
                      </div>
                      <span className="ml-auto flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-emerald-300">
                        <Wifi className="h-2.5 w-2.5" /> online
                      </span>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      <span className="chip bg-cyan-400/10 text-cyan-200">{account.role}</span>
                      <span className="key-badge">{shortFp(account.fingerprint)}</span>
                    </div>
                  </div>

                  {accounts.length > 1 && (
                    <div className="border-b border-slate-800/80 p-1.5">
                      <p className="px-2 py-1 text-[9px] font-bold uppercase tracking-[0.18em] text-slate-600">
                        Switch account
                      </p>
                      {accounts
                        .filter((entry) => entry.email !== account.email)
                        .map((entry) => (
                          <button
                            key={entry.email}
                            role="menuitem"
                            onClick={() => {
                              void signIn(entry.email);
                              setMenuOpen(false);
                            }}
                            className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-slate-800/70"
                          >
                            <span className="text-sm">{entry.avatar}</span>
                            <span className="min-w-0 flex-1">
                              <span className="block truncate text-xs font-semibold text-slate-200">
                                {entry.displayName}
                              </span>
                              <span className="block truncate font-mono text-[9px] text-slate-500">
                                {entry.email}
                              </span>
                            </span>
                            <KeyRound className="h-3 w-3 text-slate-600" />
                          </button>
                        ))}
                    </div>
                  )}

                  <div className="p-1.5">
                    <button
                      role="menuitem"
                      onClick={() => {
                        setAuthOpen(true);
                        setMenuOpen(false);
                      }}
                      className="flex w-full items-center gap-2 rounded-lg px-2 py-2 text-xs font-semibold text-slate-300 transition-colors hover:bg-slate-800/70 hover:text-white"
                    >
                      <UserRound className="h-3.5 w-3.5 text-slate-500" />
                      Switch account / add identity
                    </button>
                    <button
                      role="menuitem"
                      onClick={() => {
                        setKeysOpen(true);
                        setMenuOpen(false);
                      }}
                      className="flex w-full items-center gap-2 rounded-lg px-2 py-2 text-xs font-semibold text-slate-300 transition-colors hover:bg-slate-800/70 hover:text-white"
                    >
                      <KeyRound className="h-3.5 w-3.5 text-slate-500" />
                      Export / import keys
                    </button>
                    <button
                      role="menuitem"
                      onClick={() => {
                        signOut();
                        setMenuOpen(false);
                      }}
                      className="flex w-full items-center gap-2 rounded-lg px-2 py-2 text-xs font-semibold text-rose-300 transition-colors hover:bg-rose-500/10"
                    >
                      <LogOut className="h-3.5 w-3.5" />
                      Sign out
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <button
              onClick={() => setAuthOpen(true)}
              className="flex items-center gap-1.5 rounded-lg bg-cyan-400 px-3 py-1.5 text-[11px] font-black uppercase tracking-wider text-slate-950 shadow-glow transition-all hover:bg-cyan-300"
            >
              <LogIn className="h-3.5 w-3.5" />
              Sign in
            </button>
          )}
        </div>
      </header>

      <KeyManager open={keysOpen} onClose={() => setKeysOpen(false)} />

      {/* First-run / signed-out gate: same tabbed panel, blocks the app. */}
      <AuthModal
        open={gateOpen}
        mode="gate"
        onClose={() => undefined}
        initialTab={accounts.length > 0 ? "signin" : "demo"}
      />

      {/* Explicit switch-account dialog */}
      <AuthModal
        open={authOpen}
        mode="modal"
        onClose={() => setAuthOpen(false)}
        initialTab="signin"
      />
    </>
  );
}
