/**
 * CryptoShield — Phase 2 cryptographic engine.
 *
 * Isomorphic Web Crypto: runs in the browser (`window.crypto.subtle`) and in
 * Next.js API routes (`globalThis.crypto.subtle`, Node 18+). Never touches
 * DOM APIs — sanitization lives in lib/sanitize.ts.
 *
 * Scheme (hybrid encryption + digital signature, S/MIME/PGP style):
 *
 *   SEND                                    RECEIVE
 *   ────                                    ───────
 *   1. AES-256-GCM ephemeral key            1. RSA-OAEP unwrap AES key with
 *   2. AES-GCM encrypt payload JSON           recipient's PRIVATE key
 *      (random 12-byte IV, IV‖ct packed)    2. AES-GCM decrypt payload
 *   3. RSA-OAEP wrap AES key with           3. SHA-256 re-hash canonical bytes
 *      recipient's PUBLIC key               4. RSA-PSS verify signature
 *   4. SHA-256 canonical payload              against package senderPubKey
 *   5. RSA-PSS sign with sender's           5. Bind package key to the
 *      PRIVATE key                            directory entry for the claimed
 *                                            sender — mismatch ⇒ SPOOFED
 *
 * Every step reports timing + detail through an optional `report` callback,
 * which the UI streams into the Live Transport & Packet Inspector.
 */

import type {
  CryptoStepInput,
  DirectoryEntry,
  EmailPayload,
  SecureEnvelope,
  SecurePayload,
  SenderPublicKeys,
  VerificationResult,
} from "@/lib/types";

/* ------------------------------------------------------------------ */
/* Algorithm parameters                                                */
/* ------------------------------------------------------------------ */

const AES_PARAMS = { name: "AES-GCM", length: 256 } as const;
const IV_BYTES = 12; // NIST-recommended AES-GCM IV length
const WRAP_PARAMS = { name: "RSA-OAEP", hash: "SHA-256" } as const;
/** importKey needs RsaHashedImportParams (hash), NOT the saltLength used by sign/verify. */
const SIGN_IMPORT_PARAMS = { name: "RSA-PSS", hash: "SHA-256" } as const;
const SIGN_PARAMS = { name: "RSA-PSS", saltLength: 32 } as const; // SHA-256 → 32-byte salt
const HASH_NAME = "SHA-256" as const;

/** Receives one timed pipeline step (wired to TransportContext). */
export type StepReporter = (step: CryptoStepInput) => void;

/* ------------------------------------------------------------------ */
/* Base64 + hashing helpers                                            */
/* ------------------------------------------------------------------ */

/** Uint8Array → base64 (isomorphic: btoa exists in browsers and Node ≥16). */
export function bytesToBase64(bytes: Uint8Array<ArrayBuffer>): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

/** base64 → Uint8Array. */
export function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** SHA-256 digest as uppercase hex. */
export async function sha256Hex(data: Uint8Array<ArrayBuffer> | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const digest = await crypto.subtle.digest(HASH_NAME, bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/**
 * Canonical, deterministic byte representation of a payload for signing.
 * FIXED key order — both sides must serialize identically for RSA-PSS to
 * verify (a JSON with shuffled keys would hash differently).
 */
export function canonicalPayloadBytes(payload: SecurePayload): Uint8Array<ArrayBuffer> {
  const canonical = JSON.stringify({
    sender: payload.sender,
    recipient: payload.recipient,
    subject: payload.subject,
    body: payload.body,
    timestamp: payload.timestamp,
  });
  return new TextEncoder().encode(canonical);
}

/**
 * Stable fingerprint of a public JWK (SHA-256 over its identity fields).
 * Only `kty/n/e/alg` participate, so the same key always fingerprints the
 * same regardless of export ordering or extra metadata.
 */
export async function jwkFingerprint(jwk: JsonWebKey): Promise<string> {
  return sha256Hex(
    JSON.stringify({ kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg }),
  );
}

/* ------------------------------------------------------------------ */
/* Key import (JWK → CryptoKey)                                        */
/* ------------------------------------------------------------------ */

/**
 * Import a private RSA-PSS JWK. Non-essential JWK fields (`alg`, `use`,
 * `key_ops`) are stripped first: implementations disagree on how strictly
 * they validate `alg`, and we always pass explicit algorithm parameters.
 */
export async function importSigningKey(privateJwk: JsonWebKey): Promise<CryptoKey> {
  const jwk = { ...privateJwk };
  delete jwk.alg;
  delete jwk.use;
  delete jwk.key_ops;
  return crypto.subtle.importKey("jwk", jwk, SIGN_IMPORT_PARAMS, false, ["sign"]);
}

/** Import a public RSA-OAEP JWK (for wrapping the AES key). */
export async function importWrapPublicKey(publicJwk: JsonWebKey): Promise<CryptoKey> {
  const jwk = { ...publicJwk };
  delete jwk.alg;
  delete jwk.use;
  delete jwk.key_ops;
  return crypto.subtle.importKey("jwk", jwk, WRAP_PARAMS, true, ["encrypt"]);
}

/** Import a private RSA-OAEP JWK (for unwrapping the AES key). */
export async function importWrapPrivateKey(privateJwk: JsonWebKey): Promise<CryptoKey> {
  const jwk = { ...privateJwk };
  delete jwk.alg;
  delete jwk.use;
  delete jwk.key_ops;
  return crypto.subtle.importKey("jwk", jwk, WRAP_PARAMS, false, ["decrypt"]);
}

/* ------------------------------------------------------------------ */
/* Timing wrapper — every pipeline step is measured and reported       */
/* ------------------------------------------------------------------ */

async function step<T>(
  report: StepReporter | undefined,
  phase: CryptoStepInput["phase"],
  label: string,
  detail: (result: T) => string,
  operation: () => Promise<T>,
): Promise<T> {
  const started = performance.now();
  try {
    const result = await operation();
    report?.({
      phase,
      label,
      detail: detail(result),
      durationMs: performance.now() - started,
      status: "ok",
    });
    return result;
  } catch (cause) {
    report?.({
      phase,
      label,
      detail: `${label} FAILED: ${cause instanceof Error ? cause.message : String(cause)}`,
      durationMs: performance.now() - started,
      status: "fail",
    });
    throw cause;
  }
}

/* ------------------------------------------------------------------ */
/* SENDER identity used while packaging a secure message               */
/* ------------------------------------------------------------------ */

export interface SenderIdentity {
  /** Claimed From address (goes into the signed payload). */
  address: string;
  /** Published public keys that travel in `senderPubKey`. */
  publicKey: SenderPublicKeys;
  /** Private RSA-PSS signing key — either a live CryptoKey or a JWK. */
  signingPriv: CryptoKey | JsonWebKey;
}

/* ------------------------------------------------------------------ */
/* 1. HYBRID ENCRYPTION + SIGNING (send)                               */
/* ------------------------------------------------------------------ */

export async function hybridEncrypt(
  payload: SecurePayload,
  recipientEncPub: JsonWebKey,
  sender: SenderIdentity,
  report?: StepReporter,
): Promise<SecureEnvelope> {
  // ── Step 1: ephemeral AES-256-GCM key generation ──────────────────
  const aesKey = await step(
    report,
    "keygen",
    "AES-256-GCM key generation",
    () => "ephemeral 256-bit symmetric key generated (extractable for wrapping)",
    () => crypto.subtle.generateKey(AES_PARAMS, true, ["encrypt", "decrypt"]),
  );

  // ── Step 2: AES-GCM payload encryption ────────────────────────────
  const { packed } = await step(
    report,
    "encrypt",
    "AES-GCM payload encryption",
    (r) =>
      `${r.plainBytes} plaintext bytes → ${r.ctBytes} ciphertext bytes (12-byte random IV)`,
    async () => {
      const ivBytes = crypto.getRandomValues(new Uint8Array(IV_BYTES));
      const plainBytes = canonicalPayloadBytes(payload);
      const ct = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: ivBytes },
          aesKey,
          plainBytes,
        ),
      );
      // IV travels with the ciphertext (public by design) — packed as IV‖ct.
      const packed = new Uint8Array(ivBytes.length + ct.length);
      packed.set(ivBytes, 0);
      packed.set(ct, ivBytes.length);
      return { packed, plainBytes: plainBytes.length, ctBytes: ct.length };
    },
  );

  // ── Step 3: RSA-OAEP wrap of the AES key ──────────────────────────
  const rawAes = await crypto.subtle.exportKey("raw", aesKey);
  const encryptedSymmetricKey = await step(
    report,
    "encrypt",
    "RSA-OAEP key encryption (recipient public key)",
    (wrapped) =>
      `32-byte AES key wrapped with RSA-OAEP-256 → ${wrapped.length} bytes`,
    async () => {
      const recipientKey = await importWrapPublicKey(recipientEncPub);
      return bytesToBase64(
        new Uint8Array(
          await crypto.subtle.encrypt(WRAP_PARAMS, recipientKey, rawAes),
        ),
      );
    },
  );

  // ── Step 4: SHA-256 digest of the canonical payload ───────────────
  const digestHex = await step(
    report,
    "hash",
    "SHA-256 hashing",
    (hex) => `digest ${hex.slice(0, 32)}… (${hex.length / 2} bytes)`,
    () => sha256Hex(canonicalPayloadBytes(payload)),
  );

  // ── Step 5: RSA-PSS signature with the sender's private key ───────
  const signature = await step(
    report,
    "sign",
    "RSA-PSS digital signature",
    (sig) =>
      `signed SHA-256 digest (32-byte salt) with sender private key → ${sig.length} chars base64`,
    async () => {
      const signingKey =
        sender.signingPriv instanceof CryptoKey
          ? sender.signingPriv
          : await importSigningKey(sender.signingPriv);
      const sig = new Uint8Array(
        await crypto.subtle.sign(SIGN_PARAMS, signingKey, canonicalPayloadBytes(payload)),
      );
      return bytesToBase64(sig);
    },
  );

  return {
    payloadCiphertext: bytesToBase64(packed),
    encryptedSymmetricKey,
    signature,
    senderPubKey: sender.publicKey,
  };
}

/* ------------------------------------------------------------------ */
/* 2. VERIFICATION helpers (receive)                                   */
/* ------------------------------------------------------------------ */

/** Check that a package's public keys match the directory binding. */
async function checkKeyBinding(
  packageKeys: SenderPublicKeys,
  directoryEntry: DirectoryEntry | null,
  claimedSender: string,
): Promise<VerificationResult> {
  if (!directoryEntry) {
    return {
      status: "spoofed-unverified",
      reason: `No public key is registered for ${claimedSender} — sender identity cannot be confirmed.`,
    };
  }

  const [actual, expected] = await Promise.all([
    jwkFingerprint(packageKeys.signing),
    jwkFingerprint(directoryEntry.signingPub),
  ]);

  // Compare raw moduli too — the binding must be exact.
  const signingMatch = packageKeys.signing.n === directoryEntry.signingPub.n;
  const encryptionMatch =
    packageKeys.encryption.n === directoryEntry.encryptionPub.n;

  if (!signingMatch || !encryptionMatch) {
    return {
      status: "spoofed-unverified",
      reason: `Key binding FAILED: the key used to sign this message is not the key registered for ${claimedSender} (key-substitution / spoofing attempt).`,
      fingerprint: actual,
      expectedFingerprint: expected,
    };
  }

  return {
    status: "verified",
    reason: `Sender key matches the directory registration for ${claimedSender}.`,
    fingerprint: actual,
    expectedFingerprint: expected,
  };
}

/**
 * Verify an RSA-PSS signature over a known payload (no decryption needed —
 * used for the sender's own local plaintext copies).
 */
export async function verifyPayloadSignature(
  payload: SecurePayload,
  signatureB64: string,
  packageKeys: SenderPublicKeys,
  directoryEntry: DirectoryEntry | null,
  report?: StepReporter,
): Promise<VerificationResult> {
  // Directory binding FIRST: never trust a self-declared key.
  const binding = await checkKeyBinding(packageKeys, directoryEntry, payload.sender);
  if (binding.status !== "verified") {
    report?.({
      phase: "verify",
      label: "Sender key binding check",
      detail: binding.reason,
      durationMs: 0,
      status: "fail",
    });
    return binding;
  }

  const verified = await step(
    report,
    "verify",
    "RSA-PSS signature verification",
    (ok) =>
      ok
        ? "signature valid over canonical payload (SHA-256 + RSA-PSS)"
        : "SIGNATURE MISMATCH — payload was altered or signed with the wrong key",
    async () => {
      const jwk = { ...packageKeys.signing };
      delete jwk.alg;
      delete jwk.use;
      delete jwk.key_ops;
      const publicKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        SIGN_IMPORT_PARAMS,
        false,
        ["verify"],
      );
      return crypto.subtle.verify(
        SIGN_PARAMS,
        publicKey,
        base64ToBytes(signatureB64),
        canonicalPayloadBytes(payload),
      );
    },
  ).catch(() => {
    // step() already reported the failure — just treat the signature as invalid.
    return false;
  });

  if (!verified) {
    return {
      status: "spoofed-tampered",
      reason:
        "Digital signature INVALID — the content was modified in transit or the signature was forged.",
      fingerprint: await jwkFingerprint(packageKeys.signing),
      expectedFingerprint: binding.expectedFingerprint,
    };
  }

  // ── Certificate status gate (CRL simulation) ──────────────────────
  // Identity (binding) and integrity (signature) are both fine — the math
  // checks out. S/MIME additionally consults the Certificate Revocation List:
  // a revoked certificate must be rejected EVEN THOUGH the signature is
  // mathematically valid. This is the whole point of the CRL demonstration.
  if (directoryEntry?.revoked) {
    const fingerprint = await jwkFingerprint(packageKeys.signing);
    report?.({
      phase: "verify",
      label: "Certificate revocation check (CRL)",
      detail: `signature VALID, but the certificate for ${payload.sender} is REVOKED${
        directoryEntry.revokeReason ? ` (${directoryEntry.revokeReason})` : ""
      } — message rejected`,
      durationMs: 0,
      status: "fail",
    });
    return {
      status: "revoked",
      reason: `Certificate REVOKED for ${payload.sender} — the RSA-PSS signature is mathematically valid, but the certificate is on the Certificate Revocation List${
        directoryEntry.revokeReason ? ` (${directoryEntry.revokeReason})` : ""
      }, so S/MIME rejects the message.`,
      revoked: true,
      fingerprint,
      expectedFingerprint: binding.expectedFingerprint,
    };
  }

  return binding; // verified + binding OK
}

/* ------------------------------------------------------------------ */
/* 3. DECRYPT + VERIFY (receive)                                       */
/* ------------------------------------------------------------------ */

export interface DecryptOutcome {
  payload: SecurePayload | null;
  verification: VerificationResult;
  /**
   * Which pipeline stage failed — lets the UI distinguish "tampered with"
   * (unwrap OK, GCM tag failed) from "not encrypted to me" (unwrap failed).
   */
  failedStage?: "unwrap" | "decrypt" | "payload";
}

/**
 * Full receive-side pipeline for a secure message:
 * unwrap → decrypt → hash → verify → bind to directory.
 * Never throws — failures are reported through `verification` so the UI can
 * render a SPOOFED / TAMPERED banner instead of crashing.
 */
export async function decryptAndVerify(
  email: EmailPayload,
  recipientEncPrivJwk: JsonWebKey,
  directoryEntry: DirectoryEntry | null,
  report?: StepReporter,
): Promise<DecryptOutcome> {
  const fail = (
    reason: string,
    failedStage?: "unwrap" | "decrypt" | "payload",
  ): DecryptOutcome => ({
    payload: null,
    verification: { status: "spoofed-tampered", reason },
    failedStage,
  });

  if (
    !email.ciphertext ||
    !email.symmetricKey ||
    !email.signature ||
    !email.senderPubKey
  ) {
    return fail(
      "Message is missing parts of the secure envelope (incomplete package).",
      "payload",
    );
  }

  let rawAes: Uint8Array<ArrayBuffer>;
  try {
    // ── Step 1: RSA-OAEP unwrap of the AES key ──────────────────────
    rawAes = await step(
      report,
      "decrypt",
      "RSA-OAEP key unwrapping (recipient private key)",
      (bytes) => `AES key recovered from ${bytes.length}-byte RSA-OAEP blob`,
      async () => {
        const privateKey = await importWrapPrivateKey(recipientEncPrivJwk);
        return new Uint8Array(
          await crypto.subtle.decrypt(
            WRAP_PARAMS,
            privateKey,
            base64ToBytes(email.symmetricKey!),
          ),
        );
      },
    );
  } catch (cause) {
    // Unwrap failed ⇒ the AES key was wrapped to a DIFFERENT recipient's
    // key — this message was not encrypted to us (not tampering).
    return fail(
      `Decryption failed (wrong recipient key): ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
      "unwrap",
    );
  }

  let plainBytes: Uint8Array<ArrayBuffer>;
  try {
    // ── Step 2: AES-GCM payload decryption ──────────────────────────
    plainBytes = await step(
      report,
      "decrypt",
      "AES-GCM payload decryption",
      (bytes) => `${bytes.length} plaintext bytes recovered (IV split from packed ciphertext)`,
      async () => {
        const packed = base64ToBytes(email.ciphertext!);
        if (packed.length <= IV_BYTES) throw new Error("ciphertext too short");
        const ivBytes = packed.subarray(0, IV_BYTES);
        const ctBytes = packed.subarray(IV_BYTES);
        const aesKey = await crypto.subtle.importKey(
          "raw",
          rawAes,
          AES_PARAMS,
          false,
          ["decrypt"],
        );
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: ivBytes },
          aesKey,
          ctBytes,
        );
        return new Uint8Array(decrypted);
      },
    );
  } catch (cause) {
    // Unwrap succeeded but the GCM authentication tag failed ⇒ the bytes
    // were altered in transit. This is the Phase 3 MITM detection.
    return fail(
      `Tampering Detected — AES-GCM authentication failed: the ciphertext was altered in transit (or it was encrypted to a different recipient). Detail: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
      "decrypt",
    );
  }

  let payload: SecurePayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(plainBytes)) as SecurePayload;
    if (!payload || typeof payload.body !== "string") {
      return fail("Decrypted payload has an unexpected structure.", "payload");
    }
  } catch {
    return fail("Decrypted payload is not valid JSON — content is corrupt.", "payload");
  }

  // ── Steps 3–5: hash → signature verify → directory binding ────────
  await step(
    report,
    "hash",
    "SHA-256 re-hashing (decrypted payload)",
    (hex) => `digest ${hex.slice(0, 32)}… recomputed for verification`,
    () => sha256Hex(canonicalPayloadBytes(payload)),
  );

  const verification = await verifyPayloadSignature(
    payload,
    email.signature!,
    email.senderPubKey!,
    directoryEntry,
    report,
  );

  return { payload, verification };
}
