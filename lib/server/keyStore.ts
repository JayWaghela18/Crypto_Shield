/**
 * Server-side public key directory (the lab's simulated PKI / LDAP).
 *
 * - "browser" entries: public keys a live client registers for itself. These
 *   are persisted to `.data/cryptoshield-store.json`, so reloading the dev
 *   server keeps every registered account addressable.
 * - "demo" entries: server-generated identities for the fixed demo addresses
 *   (Bob, CEO, bank) so a fresh browser can always address mail without first
 *   creating those accounts. Their private keys are non-extractable and never
 *   leave this module.
 *
 * ⚠ Only PUBLIC material ever leaves this module (the API route serializes a
 * strict allowlist). Private keys never reach the network.
 */

import type { DirectoryEntry, RevokedCertificate, UserKeyPair } from "@/lib/types";
import { jwkFingerprint } from "@/lib/crypto";
import {
  readPersistedStore,
  updatePersistedStore,
  type PersistedKeyEntry,
} from "@/lib/server/persistence";
import { DEMO_USERS } from "@/lib/constants";

interface RegisteredEntry extends PersistedKeyEntry {
  /** Server-only private pairs for demo identities (never serialized). */
  privatePairs?: { encryption: CryptoKeyPair; signing: CryptoKeyPair };
}

interface KeyRegistry {
  entries: Map<string, RegisteredEntry>;
  hydrated: boolean;
}

const globalStore = globalThis as unknown as { __cryptoshieldKeys?: KeyRegistry };

function registry(): KeyRegistry {
  if (!globalStore.__cryptoshieldKeys) {
    const persisted = readPersistedStore();
    globalStore.__cryptoshieldKeys = {
      entries: new Map(
        persisted.keys.map((entry) => [entry.address.toLowerCase(), { ...entry }]),
      ),
      hydrated: true,
    };
  }
  return globalStore.__cryptoshieldKeys;
}

/** Strip a JWK down to its public, non-sensitive fields (defense in depth). */
export function sanitizePublicJwk(jwk: JsonWebKey): JsonWebKey {
  const clean: JsonWebKey = {
    kty: jwk.kty,
    n: jwk.n,
    e: jwk.e,
    alg: jwk.alg,
    ext: jwk.ext ?? true,
  };
  if (!clean.kty || !clean.n || !clean.e) {
    throw new Error("invalid public key: kty/n/e are required");
  }
  return clean;
}

/** Persist the browser-registered slice of the directory. */
function persistEntries(): void {
  const browserEntries: PersistedKeyEntry[] = [...registry().entries.values()]
    .filter((entry) => entry.source === "browser")
    .map(({ privatePairs: _privatePairs, ...entry }) => entry);
  updatePersistedStore((store) => {
    store.keys = browserEntries;
  });
}

/** Public-only view of an entry (what /api/keys serializes). */
function publicView(entry: RegisteredEntry): DirectoryEntry {
  return {
    address: entry.address,
    encryptionPub: entry.encryptionPub,
    signingPub: entry.signingPub,
    fingerprint: entry.fingerprint,
    source: entry.source,
    name: entry.name,
    role: entry.role,
    createdAt: entry.createdAt,
    revoked: entry.revoked ?? false,
    ...(entry.revoked ? { revokedAt: entry.revokedAt, revokeReason: entry.revokeReason } : {}),
  };
}

/** Generate a demo identity (Bob/CEO/bank) with non-extractable private keys. */
async function ensureDemoIdentity(address: string): Promise<RegisteredEntry> {
  const reg = registry();
  const existing = reg.entries.get(address);
  if (existing) return existing;

  const [encryption, signing] = await Promise.all([
    crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      /* extractable */ false, // private key can never be exported
      ["encrypt", "decrypt"],
    ),
    crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      false,
      ["sign", "verify"],
    ),
  ]);

  const [encryptionPub, signingPub] = await Promise.all([
    crypto.subtle.exportKey("jwk", encryption.publicKey),
    crypto.subtle.exportKey("jwk", signing.publicKey),
  ]);

  const demoProfile = DEMO_USERS.find((u) => u.email === address);

  const entry: RegisteredEntry = {
    address,
    encryptionPub,
    signingPub,
    fingerprint: await jwkFingerprint(signingPub),
    source: "demo",
    name: demoProfile?.displayName,
    role: demoProfile?.role,
    createdAt: Date.now(),
    privatePairs: { encryption, signing },
  };
  reg.entries.set(address, entry);
  return entry;
}

/** Look up a directory entry (lazily creating demo identities). */
export async function getEntry(address: string): Promise<DirectoryEntry | null> {
  const normalized = address.trim().toLowerCase();
  const existing = registry().entries.get(normalized);
  if (existing) return publicView(existing);

  const isDemo = DEMO_USERS.some((u) => u.email === normalized);
  if (isDemo) return publicView(await ensureDemoIdentity(normalized));
  return null;
}

/**
 * Every address a message can be sent to: registered browser accounts plus the
 * fixed demo identities. Used by the compose recipient picker.
 */
export async function listEntries(): Promise<DirectoryEntry[]> {
  const reg = registry();
  for (const demo of DEMO_USERS) {
    if (!reg.entries.has(demo.email)) await ensureDemoIdentity(demo.email);
  }
  return [...reg.entries.values()]
    .map(publicView)
    .sort((a, b) => a.address.localeCompare(b.address));
}

/** The signed-in account's own registered keys, or null. */
export async function getRegisteredAccount(address: string): Promise<DirectoryEntry | null> {
  const entry = registry().entries.get(address.trim().toLowerCase());
  return entry ? publicView(entry) : null;
}

/** Register (or rotate) the public keys for a live browser identity. */
export async function registerBrowserKeys(
  address: string,
  encryptionPub: JsonWebKey,
  signingPub: JsonWebKey,
  meta?: { name?: string; role?: string },
): Promise<DirectoryEntry> {
  const normalized = address.trim().toLowerCase();
  const encClean = sanitizePublicJwk(encryptionPub);
  const signClean = sanitizePublicJwk(signingPub);
  const previous = registry().entries.get(normalized);

  const entry: RegisteredEntry = {
    address: normalized,
    encryptionPub: encClean,
    signingPub: signClean,
    fingerprint: await jwkFingerprint(signClean),
    source: "browser",
    name: meta?.name?.trim() || previous?.name,
    role: meta?.role?.trim() || previous?.role,
    createdAt: previous?.createdAt ?? Date.now(),
    // A browser registration supersedes any demo key material for this address.
  };
  registry().entries.set(normalized, entry);
  persistEntries();
  return publicView(entry);
}

/** Convenience for the registration endpoint: keys derived from a UserKeyPair. */
export async function registerUserKeyPair(
  address: string,
  keyPair: UserKeyPair,
  meta?: { name?: string; role?: string },
): Promise<DirectoryEntry> {
  return registerBrowserKeys(
    address,
    keyPair.encryption.publicKey,
    keyPair.signing.publicKey,
    meta,
  );
}

/**
 * CRL SIMULATION — revoke (or reinstate) an address's certificate.
 *
 * Revoking does NOT touch the key material: the signature keeps verifying,
 * which is exactly the point. Verification must consult this list separately
 * and reject the message anyway (see `verifyPayloadSignature` in
 * `lib/crypto.ts`). Returns null for an unknown, non-demo address.
 */
export async function setRevocation(
  address: string,
  revoked: boolean,
  reason?: string,
): Promise<DirectoryEntry | null> {
  const normalized = address.trim().toLowerCase();
  let entry = registry().entries.get(normalized);
  if (!entry) {
    const isDemo = DEMO_USERS.some((u) => u.email === normalized);
    if (!isDemo) return null;
    entry = await ensureDemoIdentity(normalized);
  }

  entry.revoked = revoked;
  entry.revokedAt = revoked ? Date.now() : undefined;
  entry.revokeReason = revoked
    ? reason?.trim() || "unspecified (demo CRL)"
    : undefined;

  if (entry.source === "browser") persistEntries();
  return publicView(entry);
}

/** The simulated Certificate Revocation List (all currently revoked entries). */
export function listRevoked(): RevokedCertificate[] {
  return [...registry().entries.values()]
    .filter((e) => e.revoked)
    .map((e) => ({
      address: e.address,
      fingerprint: e.fingerprint,
      revokedAt: e.revokedAt ?? 0,
      revokeReason: e.revokeReason ?? "unspecified (demo CRL)",
    }));
}
