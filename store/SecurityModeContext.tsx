"use client";

/**
 * Global security mode state — powers the navbar's
 * [Unsafe Mode] <-> [Secure Mode (CryptoShield)] switch.
 *
 * Everything downstream (mail engine, rendering, transport packets) reads
 * this flag, so flipping the toggle instantly changes app-wide behavior.
 */

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { SecurityMode } from "@/lib/types";

interface SecurityModeContextValue {
  mode: SecurityMode;
  isSecure: boolean;
  setMode: (mode: SecurityMode) => void;
  /** Flip between unsafe and secure. */
  toggleMode: () => void;
}

const SecurityModeContext = createContext<SecurityModeContextValue | null>(null);

export function SecurityModeProvider({ children }: { children: ReactNode }) {
  // Phase 1 starts in UNSAFE mode so the vulnerability demos are front-and-center.
  const [mode, setMode] = useState<SecurityMode>("unsafe");

  const toggleMode = useCallback(() => {
    setMode((current) => (current === "unsafe" ? "secure" : "unsafe"));
  }, []);

  const value = useMemo<SecurityModeContextValue>(
    () => ({ mode, isSecure: mode === "secure", setMode, toggleMode }),
    [mode, toggleMode],
  );

  return (
    <SecurityModeContext.Provider value={value}>
      {children}
    </SecurityModeContext.Provider>
  );
}

/** Read the current security mode. Throws if used outside the provider. */
export function useSecurityMode(): SecurityModeContextValue {
  const ctx = useContext(SecurityModeContext);
  if (!ctx) throw new Error("useSecurityMode must be used within SecurityModeProvider");
  return ctx;
}
