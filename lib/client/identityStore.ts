/**
 * Browser-side storage for the local account's private keys.
 *
 * There is no sign-in in this build, so the keys live in this browser:
 * `localStorage` keeps them across reloads, scoped to this origin. They are
 * never uploaded — the server only ever receives the public bundle.
 *
 * ⚠ Trade-off: `localStorage` is readable by same-origin JavaScript, so a
 * successful XSS in this origin could exfiltrate the keys. The secure renderer
 * sanitizes mail, but a production client should keep keys in memory only and
 * re-prompt for a passphrase.
 */

import type { IdentityPrivateKeys } from "@/lib/crypto/identity";

const STORAGE_KEY = "cryptoshield.local-identity.v1";

function storage(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function hasPrivateExponents(keys: unknown): keys is IdentityPrivateKeys {
  if (typeof keys !== "object" || keys === null) return false;
  const candidate = keys as Partial<IdentityPrivateKeys>;
  return (
    typeof candidate.encryption?.d === "string" &&
    typeof candidate.signing?.d === "string"
  );
}

export function saveIdentity(keys: IdentityPrivateKeys): void {
  try {
    storage()?.setItem(STORAGE_KEY, JSON.stringify(keys));
  } catch {
    // Quota/privacy errors are non-fatal: the in-memory copy still works.
  }
}

export function readIdentity(): IdentityPrivateKeys | null {
  const raw = storage()?.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as unknown;
    return hasPrivateExponents(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function clearIdentity(): void {
  try {
    storage()?.removeItem(STORAGE_KEY);
  } catch {
    // Ignore storage failures — nothing else depends on the removal.
  }
}
