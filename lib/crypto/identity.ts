/**
 * CryptoShield — client-side identity key material.
 *
 * The browser is the only place a private key ever exists in the clear:
 *
 *   1. On registration the page generates TWO RSA-2048 pairs with the native
 *      Web Crypto API:
 *        • encryption — RSA-OAEP/SHA-256, wraps per-message AES-256 keys
 *        • signing    — RSA-PSS/SHA-256, authenticates the sender
 *   2. Only the PUBLIC halves are sent to `/api/identity`.
 *   3. The private halves stay in this browser. `encryptPrivateKeys()` can wrap
 *      them in a password-derived AES-256-GCM backup (PBKDF2-SHA256) for
 *      callers that need a portable copy; the demo does not upload one.
 *
 * This module is isomorphic (browser + Node ≥ 18) so it can be unit tested
 * against the real Web Crypto implementation.
 */

export interface IdentityPublicKeys {
  encryption: JsonWebKey;
  signing: JsonWebKey;
}

export interface IdentityPrivateKeys {
  encryption: JsonWebKey;
  signing: JsonWebKey;
}

export interface IdentityKeyMaterial {
  publicKeys: IdentityPublicKeys;
  privateKeys: IdentityPrivateKeys;
}

/** Password-encrypted private-key backup (the only form sent to a server). */
export interface EncryptedPrivateKeyBackup {
  v: 1;
  kdf: "PBKDF2-SHA256";
  iterations: number;
  cipher: "AES-256-GCM";
  /** base64, 16–64 bytes. */
  salt: string;
  /** base64, 12 bytes (GCM nonce). */
  iv: string;
  /** base64, AES-GCM ciphertext ‖ 128-bit tag. */
  ciphertext: string;
}

export const RSA_MODULUS_LENGTH = 2048;
export const DEFAULT_KDF_ITERATIONS = 210_000;

const BACKUP_AAD = "freebuff.identity-backup.v1";
const SALT_BYTES = 16;
const IV_BYTES = 12;
const PUBLIC_EXPONENT = new Uint8Array([0x01, 0x00, 0x01]);

function requireSubtle(): SubtleCrypto {
  const webCrypto = globalThis.crypto;
  if (!webCrypto?.subtle) {
    throw new Error(
      "Web Crypto API is unavailable. Use a modern browser (or Node 18+) over a secure context (https or localhost).",
    );
  }
  return webCrypto.subtle;
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Narrow a byte array to a plain ArrayBuffer-backed view. TypeScript 5.9's
 * `BufferSource` no longer accepts `Uint8Array<ArrayBufferLike>`.
 */
function toBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

/** base64 encode (chunked to avoid call-stack limits on large inputs). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

/** base64 decode — throws on malformed input. */
export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Generate a fresh RSA-OAEP + RSA-PSS key pair (extractable, JWK-exported). */
export async function generateIdentityKeyMaterial(): Promise<IdentityKeyMaterial> {
  const subtle = requireSubtle();

  const [encryptionPair, signingPair] = await Promise.all([
    subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: RSA_MODULUS_LENGTH,
        publicExponent: PUBLIC_EXPONENT,
        hash: "SHA-256",
      },
      /* extractable */ true,
      ["encrypt", "decrypt"],
    ),
    subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: RSA_MODULUS_LENGTH,
        publicExponent: PUBLIC_EXPONENT,
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    ),
  ]);

  const [encryptionPublic, encryptionPrivate, signingPublic, signingPrivate] =
    await Promise.all([
      subtle.exportKey("jwk", encryptionPair.publicKey),
      subtle.exportKey("jwk", encryptionPair.privateKey),
      subtle.exportKey("jwk", signingPair.publicKey),
      subtle.exportKey("jwk", signingPair.privateKey),
    ]);

  return {
    publicKeys: { encryption: encryptionPublic, signing: signingPublic },
    privateKeys: { encryption: encryptionPrivate, signing: signingPrivate },
  };
}

async function deriveBackupKey(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  if (!password) throw new Error("A password is required to encrypt the key backup");
  const subtle = requireSubtle();
  const baseKey = await subtle.importKey(
    "raw",
    new TextEncoder().encode(password.normalize("NFKC")),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return subtle.deriveKey(
    { name: "PBKDF2", salt: toBufferSource(salt), iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypt the private JWKs with a key derived from the account password.
 * Used both for the server-side backup and for a future local vault unlock.
 */
export async function encryptPrivateKeys(
  privateKeys: IdentityPrivateKeys,
  password: string,
  iterations: number = DEFAULT_KDF_ITERATIONS,
): Promise<EncryptedPrivateKeyBackup> {
  if (!Number.isInteger(iterations) || iterations < 100_000) {
    throw new Error("KDF iterations must be an integer ≥ 100000");
  }
  const subtle = requireSubtle();
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = await deriveBackupKey(password, salt, iterations);

  const plaintext = new TextEncoder().encode(JSON.stringify(privateKeys));
  const ciphertext = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toBufferSource(iv),
      additionalData: new TextEncoder().encode(BACKUP_AAD),
    },
    key,
    plaintext,
  );

  return {
    v: 1,
    kdf: "PBKDF2-SHA256",
    iterations,
    cipher: "AES-256-GCM",
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

/**
 * Decrypt a backup with the account password. Throws on a wrong password or
 * tampered ciphertext (GCM authentication failure) — callers must not treat
 * those two cases differently to the user.
 */
export async function decryptPrivateKeys(
  backup: EncryptedPrivateKeyBackup,
  password: string,
): Promise<IdentityPrivateKeys> {
  if (backup.v !== 1 || backup.cipher !== "AES-256-GCM") {
    throw new Error("Unsupported backup format");
  }
  const subtle = requireSubtle();
  const salt = base64ToBytes(backup.salt);
  const iv = base64ToBytes(backup.iv);
  const key = await deriveBackupKey(password, salt, backup.iterations);

  let plaintext: ArrayBuffer;
  try {
    plaintext = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toBufferSource(iv),
        additionalData: new TextEncoder().encode(BACKUP_AAD),
      },
      key,
      toBufferSource(base64ToBytes(backup.ciphertext)),
    );
  } catch {
    throw new Error("Could not unlock the key backup — wrong password or corrupted data");
  }

  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as Partial<IdentityPrivateKeys>;
  if (!parsed.encryption || !parsed.signing) {
    throw new Error("Key backup is missing one or more private keys");
  }
  return { encryption: parsed.encryption, signing: parsed.signing };
}

/** Serialize a backup for the `encryptedPrivateKey` column / API field. */
export function serialiseBackup(backup: EncryptedPrivateKeyBackup): string {
  return JSON.stringify(backup);
}
