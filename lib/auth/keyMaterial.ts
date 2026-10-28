/**
 * Server-side validation for client-supplied key material.
 *
 * Nothing from the browser is trusted: a public JWK must be RSA, ≥2048-bit,
 * carry no private fields, and actually import into Web Crypto with the
 * algorithm it claims. Registration rejects anything else, so every stored
 * `publicKeyJwk` is guaranteed usable by the mail engine.
 */

import type {
  EncryptedPrivateKeyBackup,
  IdentityPublicKeys,
} from "@/lib/crypto/identity";

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth"] as const;
const MIN_MODULUS_BYTES = 256; // 2048 bits
const MAX_MODULUS_CHARS = 4096; // ~32k-bit upper bound; reject absurd payloads
const MIN_KDF_ITERATIONS = 100_000;
const MAX_KDF_ITERATIONS = 2_000_000;
const MAX_BACKUP_BYTES = 16 * 1024;

export type KeyMaterialField = "publicKeyJwk" | "encryptedPrivateKey";

/**
 * JWK `alg` values differ between runtimes: browsers/Node emit "PS256" for
 * RSA-PSS keys and "RSA-OAEP-256" (or the SHA-1 "RSA-OAEP") for encryption
 * keys. Accept the aliases and normalize when storing.
 */
type PublicKeyAlgorithm = "RSA-OAEP-256" | "PS256";

const ALG_ALIASES: Record<PublicKeyAlgorithm, readonly string[]> = {
  "RSA-OAEP-256": ["RSA-OAEP-256", "RSA-OAEP"],
  PS256: ["PS256", "RSA-PSS"],
};

/** A validation failure that maps onto a specific request field. */
export class KeyMaterialError extends Error {
  constructor(
    message: string,
    readonly field: KeyMaterialField,
  ) {
    super(message);
    this.name = "KeyMaterialError";
  }
}

export type PublicKeyBundle = IdentityPublicKeys;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJsonObject(value: unknown, field: KeyMaterialField, label: string) {
  if (typeof value !== "string") return value;
  if (value.length > 16_000) {
    throw new KeyMaterialError(`${label} is too large`, field);
  }
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new KeyMaterialError(`${label} is not valid JSON`, field);
  }
}

/**
 * Validate one RSA public JWK and return a sanitized copy containing only
 * public fields. Throws `KeyMaterialError` on any problem.
 */
export function assertRsaPublicJwk(
  value: unknown,
  expected: PublicKeyAlgorithm,
  label: string,
): JsonWebKey {
  if (!isRecord(value)) {
    throw new KeyMaterialError(`${label} must be a JWK object`, "publicKeyJwk");
  }

  for (const privateField of PRIVATE_JWK_FIELDS) {
    if (privateField in value) {
      throw new KeyMaterialError(
        `${label} contains private key material ("${privateField}") — never upload private keys`,
        "publicKeyJwk",
      );
    }
  }

  if (value.kty !== "RSA") {
    throw new KeyMaterialError(`${label} must be an RSA key (kty: "RSA")`, "publicKeyJwk");
  }

  const n = value.n;
  const e = value.e;
  if (typeof n !== "string" || !BASE64URL.test(n) || n.length > MAX_MODULUS_CHARS) {
    throw new KeyMaterialError(`${label} has an invalid modulus ("n")`, "publicKeyJwk");
  }
  if (typeof e !== "string" || !BASE64URL.test(e) || e.length > 16) {
    throw new KeyMaterialError(`${label} has an invalid public exponent ("e")`, "publicKeyJwk");
  }

  // n is base64url, so each character carries 6 bits.
  const modulusBits = Math.floor((n.length * 6) / 8) * 8;
  if (modulusBits < MIN_MODULUS_BYTES * 8) {
    throw new KeyMaterialError(`${label} must be at least 2048 bits`, "publicKeyJwk");
  }

  if (typeof value.alg === "string" && !ALG_ALIASES[expected].includes(value.alg)) {
    throw new KeyMaterialError(
      `${label} declares alg "${value.alg}", expected "${expected}"`,
      "publicKeyJwk",
    );
  }

  if (Array.isArray(value.key_ops)) {
    const forbidden = value.key_ops.some((op) => op === "decrypt" || op === "sign");
    if (forbidden) {
      throw new KeyMaterialError(`${label} grants private-key operations`, "publicKeyJwk");
    }
  }

  return { kty: "RSA", n, e, alg: expected, ext: true };
}

/**
 * Accepts a bundle object, a JSON string, or the `{ version, ... }` wrapper we
 * persist, and returns a validated public bundle.
 */
export function parsePublicKeyBundle(value: unknown): PublicKeyBundle {
  const parsed = parseJsonObject(value, "publicKeyJwk", "Public key bundle");
  if (!isRecord(parsed)) {
    throw new KeyMaterialError("Public key bundle must be an object", "publicKeyJwk");
  }
  if (!isRecord(parsed.encryption) || !isRecord(parsed.signing)) {
    throw new KeyMaterialError(
      "Public key bundle must contain both `encryption` and `signing` JWKs",
      "publicKeyJwk",
    );
  }
  return {
    encryption: assertRsaPublicJwk(parsed.encryption, "RSA-OAEP-256", "Encryption key"),
    signing: assertRsaPublicJwk(parsed.signing, "PS256", "Signing key"),
  };
}

/**
 * Prove the keys are usable: import them with exactly the algorithms the mail
 * engine will use. Catches malformed/oversized values that pass shape checks.
 */
export async function assertImportablePublicKeys(bundle: PublicKeyBundle): Promise<void> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("Web Crypto is unavailable in this runtime");
  }
  try {
    await Promise.all([
      subtle.importKey(
        "jwk",
        bundle.encryption,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"],
      ),
      subtle.importKey("jwk", bundle.signing, { name: "RSA-PSS", hash: "SHA-256" }, true, [
        "verify",
      ]),
    ]);
  } catch {
    throw new KeyMaterialError(
      "Public keys could not be imported — regenerate the identity and try again",
      "publicKeyJwk",
    );
  }
}

/** Canonical, order-stable public representation used for fingerprints. */
export function canonicalPublicJwk(jwk: JsonWebKey): string {
  return JSON.stringify({ kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg ?? null });
}

/** SHA-256 over the canonical public JWK, uppercase hex (like an S/MIME fingerprint). */
export async function fingerprintPublicKey(jwk: JsonWebKey): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("Web Crypto is unavailable in this runtime");
  const digest = await subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalPublicJwk(jwk)),
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/** Fingerprint of the signing key inside a stored `publicKeyJwk` string. */
export async function fingerprintStoredIdentity(publicKeyJwk: string): Promise<string> {
  const bundle = parsePublicKeyBundle(publicKeyJwk);
  return fingerprintPublicKey(bundle.signing);
}

function decodeBase64(value: string, label: string, field: KeyMaterialField): Uint8Array {
  try {
    return base64ToBytes(value);
  } catch {
    throw new KeyMaterialError(`${label} is not valid base64`, field);
  }
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Validate the encrypted-backup envelope. The server cannot check the
 * plaintext (that is the point) but it can reject malformed or oversized
 * blobs so a corrupt backup never reaches the database.
 */
export function parseEncryptedPrivateKeyBackup(value: unknown): EncryptedPrivateKeyBackup {
  const parsed = parseJsonObject(value, "encryptedPrivateKey", "Encrypted key backup");
  if (!isRecord(parsed)) {
    throw new KeyMaterialError("Encrypted key backup must be an object", "encryptedPrivateKey");
  }
  if (parsed.v !== 1) {
    throw new KeyMaterialError("Unsupported key backup version", "encryptedPrivateKey");
  }
  if (parsed.kdf !== "PBKDF2-SHA256") {
    throw new KeyMaterialError("Key backup must use PBKDF2-SHA256", "encryptedPrivateKey");
  }
  if (parsed.cipher !== "AES-256-GCM") {
    throw new KeyMaterialError("Key backup must use AES-256-GCM", "encryptedPrivateKey");
  }

  const iterations = parsed.iterations;
  if (
    typeof iterations !== "number" ||
    !Number.isInteger(iterations) ||
    iterations < MIN_KDF_ITERATIONS ||
    iterations > MAX_KDF_ITERATIONS
  ) {
    throw new KeyMaterialError(
      `Key backup iterations must be an integer between ${MIN_KDF_ITERATIONS} and ${MAX_KDF_ITERATIONS}`,
      "encryptedPrivateKey",
    );
  }

  const salt = parsed.salt;
  const iv = parsed.iv;
  const ciphertext = parsed.ciphertext;
  if (typeof salt !== "string" || typeof iv !== "string" || typeof ciphertext !== "string") {
    throw new KeyMaterialError(
      "Key backup requires salt, iv and ciphertext strings",
      "encryptedPrivateKey",
    );
  }

  const saltBytes = decodeBase64(salt, "Key backup salt", "encryptedPrivateKey");
  if (saltBytes.length < 16 || saltBytes.length > 64) {
    throw new KeyMaterialError(
      "Key backup salt must be 16–64 bytes",
      "encryptedPrivateKey",
    );
  }
  const ivBytes = decodeBase64(iv, "Key backup IV", "encryptedPrivateKey");
  if (ivBytes.length !== 12) {
    throw new KeyMaterialError("Key backup IV must be 12 bytes", "encryptedPrivateKey");
  }
  const ciphertextBytes = decodeBase64(ciphertext, "Key backup ciphertext", "encryptedPrivateKey");
  if (ciphertextBytes.length < 17 || ciphertextBytes.length > MAX_BACKUP_BYTES) {
    throw new KeyMaterialError(
      "Key backup ciphertext has an invalid length",
      "encryptedPrivateKey",
    );
  }

  return {
    v: 1,
    kdf: "PBKDF2-SHA256",
    iterations,
    cipher: "AES-256-GCM",
    salt,
    iv,
    ciphertext,
  };
}

/** Serialize the public bundle for the `publicKeyJwk` column. */
export function serialisePublicKeyBundle(bundle: PublicKeyBundle): string {
  return JSON.stringify({ version: 1, ...bundle });
}
