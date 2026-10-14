"use client";

/**
 * Current user profile — RSA-OAEP (encryption) + RSA-PSS (signing) key pairs
 * and X.509/PGP-like certificates generated with the Web Crypto API.
 *
 * Phase 2 additions:
 *  - The profile is PERSISTED in localStorage so previously received secure
 *    mail stays decryptable across reloads. ⚠ Demo tradeoff: a production app
 *    must protect private keys with a passphrase/OS keystore, not localStorage.
 *  - On boot the PUBLIC keys are registered with the server directory
 *    (/api/keys/register) — the trust root the receiver uses to detect
 *    spoofed senders. Private keys never leave this browser.
 *  - `registered` flips true once the directory knows this identity, which
 *    triggers a mailbox refresh (Bob's server-signed seed lands then).
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { UserProfile } from "@/lib/types";
import {
  buildPgpLikeCertificate,
  buildX509LikeCertificate,
  generateUserKeyPairs,
} from "@/lib/crypto/webcrypto";
import { registerPublicKey } from "@/lib/api/emailClient";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useTransport } from "@/store/TransportContext";
import { CURRENT_USER } from "@/lib/constants";

export type ProfileStatus = "generating" | "ready" | "error";

const STORAGE_KEY = "cryptoshield.profile.v2";

interface UserProfileContextValue {
  profile: UserProfile | null;
  status: ProfileStatus;
  /** True once this identity's public keys are in the server directory. */
  registered: boolean;
}

const UserProfileContext = createContext<UserProfileContextValue | null>(null);

/** Load the persisted profile (client-only; null on server or first visit). */
function loadStoredProfile(): UserProfile | null {
  try {
    if (typeof window === "undefined") return null;
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as UserProfile;
    // Structural check — a corrupt entry forces regeneration.
    if (
      parsed?.email !== CURRENT_USER ||
      !parsed?.keyPair?.encryption?.privateKey ||
      !parsed?.keyPair?.signing?.privateKey
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function storeProfile(profile: UserProfile): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(profile));
  } catch (cause) {
    console.warn("[CryptoShield] could not persist profile:", cause);
  }
}

export function UserProfileProvider({ children }: { children: ReactNode }) {
  const { mode } = useSecurityMode();
  const { recordPacket } = useTransport();

  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [status, setStatus] = useState<ProfileStatus>("generating");
  const [registered, setRegistered] = useState(false);
  const registrationAttempted = useRef(false);

  // ── 1. Load or generate the key material ──────────────────────────
  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        const stored = loadStoredProfile();
        if (stored) {
          if (cancelled) return;
          setProfile(stored);
          setStatus("ready");
          return;
        }

        const keyPair = await generateUserKeyPairs();
        const displayName = "Alice";

        const [x509, pgp] = await Promise.all([
          buildX509LikeCertificate(keyPair.signing, displayName, CURRENT_USER),
          buildPgpLikeCertificate(keyPair.signing, displayName, CURRENT_USER),
        ]);

        if (cancelled) return;
        const fresh: UserProfile = {
          id: "alice",
          displayName,
          email: CURRENT_USER,
          keyPair,
          certificate: { x509, pgp },
          createdAt: Date.now(),
        };
        storeProfile(fresh);
        setProfile(fresh);
        setStatus("ready");
      } catch (error) {
        console.error("[CryptoShield] key generation failed:", error);
        if (!cancelled) setStatus("error");
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  // ── 2. Publish PUBLIC keys to the directory (never private ones) ──
  const publishKeys = useCallback(
    async (p: UserProfile) => {
      if (registrationAttempted.current) return;
      registrationAttempted.current = true;
      try {
        await registerPublicKey(
          p.email,
          p.keyPair.encryption.publicKey,
          p.keyPair.signing.publicKey,
          mode,
          recordPacket,
        );
        setRegistered(true);
      } catch (cause) {
        console.error("[CryptoShield] directory registration failed:", cause);
        registrationAttempted.current = false; // allow retry on remount
      }
    },
    [mode, recordPacket],
  );

  useEffect(() => {
    if (profile && status === "ready") void publishKeys(profile);
  }, [profile, status, publishKeys]);

  const value = useMemo(
    () => ({ profile, status, registered }),
    [profile, status, registered],
  );

  return (
    <UserProfileContext.Provider value={value}>{children}</UserProfileContext.Provider>
  );
}

/** Access the browser-generated user profile. Throws if outside provider. */
export function useUserProfile(): UserProfileContextValue {
  const ctx = useContext(UserProfileContext);
  if (!ctx) throw new Error("useUserProfile must be used within UserProfileProvider");
  return ctx;
}
