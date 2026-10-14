/**
 * Server-side public key directory (in-memory, HMR-safe like memoryStore).
 *
 * - "browser" entries: public keys a live client registers for itself.
 * - "demo" entries: server-generated identities for Bob/CEO so messages can
 *   be encrypted TO them. Their private keys exist ONLY here (Node Web Crypto,
 *   non-extractable) — the server uses Bob's private key once to sign a
 *   genuine secure welcome message, which proves end-to-end verification
 *   works for a real remote sender, not just self-signed mail.
 *
 * ⚠ Only PUBLIC material ever leaves this module (the API route serializes
 * a strict allowlist). Private keys never reach the network.
 */

import type { DirectoryEntry, RevokedCertificate } from "@/lib/types";
import { hybridEncrypt, jwkFingerprint, type SenderIdentity } from "@/lib/crypto";
import { listEmails, storeEmail } from "@/lib/server/memoryStore";
import { CURRENT_USER, DEMO_USERS } from "@/lib/constants";

interface RegisteredEntry {
  address: string;
  encryptionPub: JsonWebKey;
  signingPub: JsonWebKey;
  fingerprint: string;
  source: "browser" | "demo";
  /** CRL simulation: revoked certificate (rejected even if signature is valid). */
  revoked?: boolean;
  revokedAt?: number;
  revokeReason?: string;
  /** Server-only private pairs for demo identities (never serialized). */
  privatePairs?: { encryption: CryptoKeyPair; signing: CryptoKeyPair };
}

interface KeyRegistry {
  entries: Map<string, RegisteredEntry>;
  seeded: boolean;
}

const globalStore = globalThis as unknown as { __cryptoshieldKeys?: KeyRegistry };

function registry(): KeyRegistry {
  if (!globalStore.__cryptoshieldKeys) {
    globalStore.__cryptoshieldKeys = { entries: new Map(), seeded: false };
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

/** Public-only view of an entry (what /api/keys serializes). */
function publicView(entry: RegisteredEntry): DirectoryEntry {
  return {
    address: entry.address,
    encryptionPub: entry.encryptionPub,
    signingPub: entry.signingPub,
    fingerprint: entry.fingerprint,
    source: entry.source,
    revoked: entry.revoked ?? false,
    ...(entry.revoked ? { revokedAt: entry.revokedAt, revokeReason: entry.revokeReason } : {}),
  };
}

/** Generate a demo identity (Bob/CEO) with server-held non-extractable keys. */
async function ensureDemoIdentity(address: string): Promise<RegisteredEntry> {
  const reg = registry();
  const existing = reg.entries.get(address);
  if (existing) return existing;

  const [encryption, signing] = await Promise.all([
    crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      /* extractable */ false, // private key can never be exported
      ["encrypt", "decrypt"],
    ),
    crypto.subtle.generateKey(
      { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      false,
      ["sign", "verify"],
    ),
  ]);

  const [encryptionPub, signingPub] = await Promise.all([
    crypto.subtle.exportKey("jwk", encryption.publicKey),
    crypto.subtle.exportKey("jwk", signing.publicKey),
  ]);

  const entry: RegisteredEntry = {
    address,
    encryptionPub,
    signingPub,
    fingerprint: await jwkFingerprint(signingPub),
    source: "demo",
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

/** Register (or rotate) the public keys for a live browser identity. */
export async function registerBrowserKeys(
  address: string,
  encryptionPub: JsonWebKey,
  signingPub: JsonWebKey,
): Promise<DirectoryEntry> {
  const normalized = address.trim().toLowerCase();
  const encClean = sanitizePublicJwk(encryptionPub);
  const signClean = sanitizePublicJwk(signingPub);

  const entry: RegisteredEntry = {
    address: normalized,
    encryptionPub: encClean,
    signingPub: signClean,
    fingerprint: await jwkFingerprint(signClean),
    source: "browser",
    // Note: any previous private pairs (demo identity) are intentionally dropped —
    // a browser registration supersedes the demo key for this address.
  };
  registry().entries.set(normalized, entry);
  return publicView(entry);
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

/**
 * Seed one genuine secure message: Bob (server-held key) → Alice.
 * Runs after Alice registers so it can be encrypted to her public key.
 * Created exactly once per server lifetime.
 */
export async function maybeSeedSecureMessage(): Promise<boolean> {
  const reg = registry();
  if (reg.seeded) return false;

  const alice = registry().entries.get(CURRENT_USER.toLowerCase());
  if (!alice) return false; // retry on next registration

  const alreadySeeded = listEmails("inbox", CURRENT_USER).some(
    (e) => e.isSecureMode && e.sender === "bob@cryptoshield.dev",
  );
  if (alreadySeeded) {
    reg.seeded = true;
    return false;
  }

  const bob = await ensureDemoIdentity("bob@cryptoshield.dev");
  if (!bob.privatePairs) return false;

  const timestamp = Date.now();
  const payload = {
    sender: "bob@cryptoshield.dev",
    recipient: CURRENT_USER,
    subject: "Hybrid-encrypted welcome — signed by my private key",
    body: "<p>Hi Alice,</p><p>This message was <b>encrypted to your RSA-OAEP public key</b> and <b>signed with my RSA-PSS private key</b>. The mail server can only forward the opaque envelope — it cannot read or forge this content.</p><p>— Bob</p>",
    timestamp,
  };

  const senderIdentity: SenderIdentity = {
    address: "bob@cryptoshield.dev",
    publicKey: { encryption: bob.encryptionPub, signing: bob.signingPub },
    signingPriv: bob.privatePairs.signing.privateKey,
  };

  const envelope = await hybridEncrypt(payload, alice.encryptionPub, senderIdentity);

  storeEmail({
    id: crypto.randomUUID(),
    sender: "bob@cryptoshield.dev",
    recipient: CURRENT_USER,
    // Decoy subject on the wire — the real one lives inside the ciphertext.
    subject: "(end-to-end encrypted)",
    body: "",
    ciphertext: envelope.payloadCiphertext,
    symmetricKey: envelope.encryptedSymmetricKey,
    signature: envelope.signature,
    senderPubKey: envelope.senderPubKey,
    isSecureMode: true,
    timestamp,
  });

  reg.seeded = true;
  return true;
}
