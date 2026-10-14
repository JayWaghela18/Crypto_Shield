/**
 * CryptoShield — Web Crypto helpers (browser-native `window.crypto.subtle`).
 *
 * Phase 1: generate the RSA key pairs + X.509/PGP-like certificates that the
 * user profile schema expects, so Phase 2 (encrypt / sign / verify) can plug
 * straight in. Nothing here touches the network; private keys never leave
 * the browser.
 */

import type {
  PgpLikeCertificate,
  RsaKeyPairMaterial,
  UserKeyPair,
  X509LikeCertificate,
} from "@/lib/types";

const RSA_MODULUS_LENGTH = 2048;
const PUBLIC_EXPONENT = new Uint8Array([0x01, 0x00, 0x01]); // 65537
const CERT_VALIDITY_YEARS = 2;

/** Export a CryptoKey pair to JWK material. Private key stays local to the caller. */
async function exportKeyPair(pair: CryptoKeyPair, algorithm: string): Promise<RsaKeyPairMaterial> {
  const [publicKey, privateKey] = await Promise.all([
    crypto.subtle.exportKey("jwk", pair.publicKey),
    crypto.subtle.exportKey("jwk", pair.privateKey),
  ]);
  return { algorithm, modulusLength: RSA_MODULUS_LENGTH, publicKey, privateKey };
}

/** RSA-OAEP key pair used to wrap the per-message AES key (Phase 2). */
export async function generateEncryptionKeyPair(): Promise<RsaKeyPairMaterial> {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: RSA_MODULUS_LENGTH,
      publicExponent: PUBLIC_EXPONENT,
      hash: "SHA-256",
    },
    /* extractable */ true,
    ["encrypt", "decrypt"],
  );
  return exportKeyPair(pair, "RSA-OAEP-256");
}

/** RSA-PSS key pair used to sign/verify messages (Phase 2). */
export async function generateSigningKeyPair(): Promise<RsaKeyPairMaterial> {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: RSA_MODULUS_LENGTH,
      publicExponent: PUBLIC_EXPONENT,
      hash: "SHA-256",
    },
    /* extractable */ true,
    ["sign", "verify"],
  );
  return exportKeyPair(pair, "RSA-PSS-256");
}

/** Generate both key pairs a profile needs (encrypt + sign). */
export async function generateUserKeyPairs(): Promise<UserKeyPair> {
  const [encryption, signing] = await Promise.all([
    generateEncryptionKeyPair(),
    generateSigningKeyPair(),
  ]);
  return { encryption, signing };
}

/** SHA-256 hash of any string, returned as uppercase hex. */
export async function sha256Hex(data: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/** Encode a JWK as base64 (used for the certificate's public key field). */
function jwkToBase64(jwk: JsonWebKey): string {
  return btoa(JSON.stringify(jwk));
}

/** Build a simplified self-signed X.509-style certificate for a public key. */
export async function buildX509LikeCertificate(
  subjectKey: RsaKeyPairMaterial,
  displayName: string,
  email: string,
): Promise<X509LikeCertificate> {
  const now = Date.now();
  const spkiBase64 = jwkToBase64(subjectKey.publicKey);
  const fingerprint = await sha256Hex(spkiBase64);
  return {
    serialNumber: fingerprint.slice(0, 32),
    subject: `CN=${displayName}, E=${email}`,
    issuer: `CN=${displayName}, E=${email}`, // self-signed
    notBefore: now,
    notAfter: now + CERT_VALIDITY_YEARS * 365 * 24 * 60 * 60 * 1000,
    publicKeyBase64: spkiBase64,
    fingerprintSha256: fingerprint,
  };
}

/** Build PGP-style certificate metadata (public key block placeholder). */
export async function buildPgpLikeCertificate(
  publicKeyMaterial: RsaKeyPairMaterial,
  displayName: string,
  email: string,
): Promise<PgpLikeCertificate> {
  const now = Date.now();
  const fingerprint = await sha256Hex(JSON.stringify(publicKeyMaterial.publicKey));
  const grouped = fingerprint.replace(/(.{4})/g, "$1 ").trim();
  return {
    version: 4,
    userId: `${displayName} <${email}>`,
    created: now,
    fingerprint,
    // Phase 2: replace with a real ASCII-armored OpenPGP public key block.
    publicKeyArmored: [
      "-----BEGIN PGP PUBLIC KEY BLOCK-----",
      ...grouped.match(/.{1,64}/g) ?? [],
      "-----END PGP PUBLIC KEY BLOCK-----",
    ].join("\n"),
    keyFlags: ["encrypt", "sign", "certify"],
  };
}
