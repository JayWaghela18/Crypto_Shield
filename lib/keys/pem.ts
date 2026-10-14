/**
 * PEM ⇄ JWK conversion for RSA key material.
 *
 * Web Crypto speaks DER (`spki` for public keys, `pkcs8` for private keys)
 * while this app works in JWK throughout. These helpers bridge the two and
 * handle the PEM base64 armor, so users can export/import real `.pem` files
 * and still feed the result straight into `lib/crypto.ts`.
 *
 * NOTE: PEM carries no algorithm or key-role metadata — an RSA private key
 * imports under either RSA-OAEP or RSA-PSS. Callers decide the role; the
 * import UI documents that mapping.
 */

import { base64ToBytes, bytesToBase64 } from "@/lib/crypto";

/** RSA algorithms this module can encode/import. */
export type RsaAlgorithm = "RSA-OAEP" | "RSA-PSS";
export type KeyDirection = "public" | "private";

const IMPORT_PARAMS: Record<RsaAlgorithm, RsaHashedImportParams> = {
  "RSA-OAEP": { name: "RSA-OAEP", hash: "SHA-256" },
  "RSA-PSS": { name: "RSA-PSS", hash: "SHA-256" },
};

/** A PEM block: armor label + the decoded DER payload. */
export interface PemBlock {
  label: string;
  der: Uint8Array<ArrayBuffer>;
}

/** Minimal JWK field sanitizer (engines disagree on `alg`/`use`/`key_ops`). */
function stripMeta(jwk: JsonWebKey): JsonWebKey {
  const copy = { ...jwk };
  delete copy.alg;
  delete copy.use;
  delete copy.key_ops;
  return copy;
}

/** Valid Web Crypto usages for importing a key in a given role. */
function usages(direction: KeyDirection, algorithm: RsaAlgorithm): KeyUsage[] {
  if (direction === "private") {
    return algorithm === "RSA-OAEP" ? ["decrypt"] : ["sign"];
  }
  return algorithm === "RSA-OAEP" ? ["encrypt"] : ["verify"];
}

/** PEM armor label for a key direction. */
export function pemLabel(direction: KeyDirection): string {
  return direction === "private" ? "PRIVATE KEY" : "PUBLIC KEY";
}

/* ------------------------------------------------------------------ */
/* Encoding                                                            */
/* ------------------------------------------------------------------ */

/** Wrap DER bytes in PEM armor (64-character lines, trailing newline). */
export function derToPem(der: ArrayBuffer | Uint8Array<ArrayBuffer>, label: string): string {
  const b64 = bytesToBase64(new Uint8Array(der));
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/** JWK → DER bytes (with the PEM label the direction implies). */
export async function jwkToDer(
  jwk: JsonWebKey,
  direction: KeyDirection,
  algorithm: RsaAlgorithm,
): Promise<{ der: Uint8Array<ArrayBuffer>; label: string }> {
  const key = await crypto.subtle.importKey(
    "jwk",
    stripMeta(jwk),
    IMPORT_PARAMS[algorithm],
    true,
    usages(direction, algorithm),
  );
  const der = new Uint8Array(
    await crypto.subtle.exportKey(direction === "private" ? "pkcs8" : "spki", key),
  );
  return { der, label: pemLabel(direction) };
}

/** JWK → PEM string (SPKI for public keys, PKCS#8 for private keys). */
export async function jwkToPem(
  jwk: JsonWebKey,
  direction: KeyDirection,
  algorithm: RsaAlgorithm,
): Promise<string> {
  const { der, label } = await jwkToDer(jwk, direction, algorithm);
  return derToPem(der, label);
}

/* ------------------------------------------------------------------ */
/* Decoding                                                            */
/* ------------------------------------------------------------------ */

/** Every PEM block found in a text blob, in order. */
export function splitPemBlocks(text: string): PemBlock[] {
  const blocks: PemBlock[] = [];
  const regex = /-----BEGIN ([^-]+)-----([\s\S]*?)-----END \1-----/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    const body = match[2].replace(/\s+/g, "");
    if (!body) continue;
    blocks.push({ label: match[1].trim(), der: base64ToBytes(body) });
  }
  return blocks;
}

/** Parse exactly one PEM block, erroring if the armor is missing/empty. */
export function pemToDer(pem: string): PemBlock {
  const blocks = splitPemBlocks(pem);
  if (blocks.length === 0) {
    throw new Error("Not a valid PEM block (missing -----BEGIN/END----- armor)");
  }
  return blocks[0];
}

/** DER → JWK. */
export async function derToJwk(
  der: Uint8Array<ArrayBuffer>,
  direction: KeyDirection,
  algorithm: RsaAlgorithm,
): Promise<JsonWebKey> {
  const key = await crypto.subtle.importKey(
    direction === "private" ? "pkcs8" : "spki",
    der,
    IMPORT_PARAMS[algorithm],
    true,
    usages(direction, algorithm),
  );
  return crypto.subtle.exportKey("jwk", key);
}

/** PEM → JWK. */
export async function pemToJwk(
  pem: string,
  direction: KeyDirection,
  algorithm: RsaAlgorithm,
): Promise<JsonWebKey> {
  return derToJwk(pemToDer(pem).der, direction, algorithm);
}
