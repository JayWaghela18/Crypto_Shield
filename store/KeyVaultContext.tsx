"use client";

/**
 * Key vault — holds an OPTIONAL externally imported identity so the mailbox can
 * attempt to decrypt third-party mail (messages encrypted to someone else's
 * public key, whose private key the user obtained out of band).
 *
 * The imported material is persisted in localStorage (same demo trade-off as
 * the user's own profile) and can be cleared at any time.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { ImportedIdentity, KeyExportFormat } from "@/lib/types";
import { bundleToImportedIdentity, parseKeyMaterial } from "@/lib/keys/bundle";

const STORAGE_KEY = "cryptoshield.imported-key.v1";

interface KeyVaultContextValue {
  /** The imported third-party identity, or null when none is loaded. */
  imported: ImportedIdentity | null;
  /**
   * Parse + store key material (JWK or PEM text). Throws with a readable
   * message when the material cannot be interpreted.
   */
  importMaterial: (text: string, format: KeyExportFormat) => Promise<ImportedIdentity>;
  /** Forget the imported identity. */
  clearImported: () => void;
}

const KeyVaultContext = createContext<KeyVaultContextValue | null>(null);

function loadStored(): ImportedIdentity | null {
  try {
    if (typeof window === "undefined") return null;
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as ImportedIdentity;
    return parsed?.encryptionPrivateKey ? parsed : null;
  } catch {
    return null;
  }
}

function persist(identity: ImportedIdentity | null): void {
  try {
    if (identity) {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(identity));
    } else {
      window.localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Storage quota/privacy errors are non-fatal for the in-memory copy.
  }
}

export function KeyVaultProvider({ children }: { children: ReactNode }) {
  const [imported, setImported] = useState<ImportedIdentity | null>(null);

  // Restore after mount to avoid a hydration mismatch.
  useEffect(() => {
    const stored = loadStored();
    if (stored) setImported(stored);
  }, []);

  const importMaterial = useCallback(
    async (text: string, format: KeyExportFormat) => {
      const bundle = await parseKeyMaterial(text, format);
      const identity = await bundleToImportedIdentity(bundle, format);
      persist(identity);
      setImported(identity);
      return identity;
    },
    [],
  );

  const clearImported = useCallback(() => {
    persist(null);
    setImported(null);
  }, []);

  const value = useMemo<KeyVaultContextValue>(
    () => ({ imported, importMaterial, clearImported }),
    [imported, importMaterial, clearImported],
  );

  return <KeyVaultContext.Provider value={value}>{children}</KeyVaultContext.Provider>;
}

/** Access the imported-key vault. Throws outside the provider. */
export function useKeyVault(): KeyVaultContextValue {
  const ctx = useContext(KeyVaultContext);
  if (!ctx) throw new Error("useKeyVault must be used within KeyVaultProvider");
  return ctx;
}
