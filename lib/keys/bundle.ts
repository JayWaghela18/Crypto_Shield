/**
 * Key bundle assembly + parsing for the Key Management UI.
 *
 * EXPORT: turn a `UserProfile` into downloadable JWK or PEM files.
 * IMPORT: turn pasted/uploaded material (a bundle, a bare JWK, a UserProfile
 *         JSON, or one-or-more PEM blocks) into an `ImportedIdentity` that the
 *         mailbox can use to attempt third-party decryption.
 *
 * ⚠ Private material never leaves this browser unless the user explicitly
 * downloads it. PEM carries no algorithm/role metadata, so the PEM import path
 * uses a documented label heuristic (see `parseKeyMaterial`).
 */

import type {
  ExportedKeyFile,
  ImportedIdentity,
  KeyBundle,
  KeyExportFormat,
  UserProfile,
} from "@/lib/types";
import { jwkFingerprint } from "@/lib/crypto";
import { derToJwk, jwkToPem, splitPemBlocks } from "@/lib/keys/pem";

/* ------------------------------------------------------------------ */
/* Export                                                              */
/* ------------------------------------------------------------------ */

/** Filename-safe slug from a free-form label/address. */
function slug(value: string): string {
  return (
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "cryptoshield"
  );
}

const JSON_MIME = "application/json";
const PEM_MIME = "application/x-pem-file";

/** Portable key bundle for a profile (private material only when asked). */
export function buildKeyBundle(profile: UserProfile, includePrivate: boolean): KeyBundle {
  const bundle: KeyBundle = {
    version: 1,
    label: profile.displayName,
    address: profile.email,
    exportedAt: Date.now(),
    encryptionPublic: profile.keyPair.encryption.publicKey,
    signingPublic: profile.keyPair.signing.publicKey,
  };
  if (includePrivate) {
    bundle.encryptionPrivate = profile.keyPair.encryption.privateKey;
    bundle.signingPrivate = profile.keyPair.signing.privateKey;
  }
  return bundle;
}

function jsonFile(filename: string, value: unknown): ExportedKeyFile {
  return { filename, mime: JSON_MIME, content: JSON.stringify(value, null, 2) };
}

/** Build every downloadable file for a profile in the requested format. */
export async function buildKeyFiles(
  profile: UserProfile,
  format: KeyExportFormat,
  includePrivate: boolean,
): Promise<ExportedKeyFile[]> {
  const base = `cryptoshield-${slug(profile.email || profile.displayName)}`;
  const bundle = buildKeyBundle(profile, includePrivate);

  if (format === "jwk") {
    const files: ExportedKeyFile[] = [
      jsonFile(`${base}-bundle.jwk.json`, bundle),
      jsonFile(`${base}-encryption-public.jwk.json`, bundle.encryptionPublic),
      jsonFile(`${base}-signing-public.jwk.json`, bundle.signingPublic),
    ];
    if (includePrivate) {
      files.push(
        jsonFile(`${base}-encryption-private.jwk.json`, bundle.encryptionPrivate),
        jsonFile(`${base}-signing-private.jwk.json`, bundle.signingPrivate),
      );
    }
    return files;
  }

  const files: ExportedKeyFile[] = [
    {
      filename: `${base}-encryption-public.pem`,
      mime: PEM_MIME,
      content: await jwkToPem(bundle.encryptionPublic!, "public", "RSA-OAEP"),
    },
    {
      filename: `${base}-signing-public.pem`,
      mime: PEM_MIME,
      content: await jwkToPem(bundle.signingPublic!, "public", "RSA-PSS"),
    },
  ];
  if (includePrivate) {
    files.push(
      {
        filename: `${base}-encryption-private.pem`,
        mime: PEM_MIME,
        content: await jwkToPem(bundle.encryptionPrivate!, "private", "RSA-OAEP"),
      },
      {
        filename: `${base}-signing-private.pem`,
        mime: PEM_MIME,
        content: await jwkToPem(bundle.signingPrivate!, "private", "RSA-PSS"),
      },
    );
  }
  return files;
}

/* ------------------------------------------------------------------ */
/* Import                                                              */
/* ------------------------------------------------------------------ */

function asJwk(value: unknown): JsonWebKey | undefined {
  if (!value || typeof value !== "object") return undefined;
  const candidate = value as JsonWebKey;
  return candidate.kty && candidate.n ? candidate : undefined;
}

/**
 * Normalize arbitrary pasted JSON into a bundle. Accepts:
 *  - a CryptoShield `KeyBundle`
 *  - a bare RSA `JsonWebKey` (private or public)
 *  - a full exported `UserProfile` (its `keyPair` is unwrapped)
 */
export function normalizeBundle(parsed: unknown): KeyBundle | null {
  if (!parsed || typeof parsed !== "object") return null;
  const obj = parsed as Record<string, unknown>;

  // Full UserProfile export
  if (obj.keyPair && typeof obj.keyPair === "object") {
    const kp = obj.keyPair as {
      encryption?: { publicKey?: JsonWebKey; privateKey?: JsonWebKey };
      signing?: { publicKey?: JsonWebKey; privateKey?: JsonWebKey };
    };
    return {
      version: 1,
      label: typeof obj.displayName === "string" ? obj.displayName : "imported",
      address: typeof obj.email === "string" ? obj.email : undefined,
      exportedAt: Date.now(),
      encryptionPublic: kp.encryption?.publicKey,
      encryptionPrivate: kp.encryption?.privateKey,
      signingPublic: kp.signing?.publicKey,
      signingPrivate: kp.signing?.privateKey,
    };
  }

  // Bare JWK
  if (obj.kty === "RSA" && obj.n) {
    const jwk = obj as JsonWebKey;
    return {
      version: 1,
      label: "imported",
      exportedAt: Date.now(),
      ...(jwk.d ? { encryptionPrivate: jwk } : { encryptionPublic: jwk }),
    };
  }

  // Bundle-shaped object
  const hasBundleField =
    obj.encryptionPrivate || obj.encryptionPublic || obj.signingPrivate || obj.signingPublic;
  if (hasBundleField) {
    return {
      version: 1,
      label: typeof obj.label === "string" ? obj.label : "imported",
      address: typeof obj.address === "string" ? obj.address : undefined,
      exportedAt: typeof obj.exportedAt === "number" ? obj.exportedAt : Date.now(),
      encryptionPublic: asJwk(obj.encryptionPublic),
      encryptionPrivate: asJwk(obj.encryptionPrivate),
      signingPublic: asJwk(obj.signingPublic),
      signingPrivate: asJwk(obj.signingPrivate),
    };
  }

  return null;
}

/**
 * Parse pasted or uploaded key material into a bundle.
 *
 * JSON is unambiguous. PEM is heuristically mapped because it lacks role
 * metadata: the first `PRIVATE KEY` block becomes the encryption private key
 * (the one needed to decrypt third-party mail), the first `PUBLIC KEY` block
 * becomes the signing public key, and a second public block becomes the
 * encryption public key.
 */
export async function parseKeyMaterial(
  text: string,
  format: KeyExportFormat,
): Promise<KeyBundle> {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("Paste or upload key material first");

  const looksJson = format === "jwk" || trimmed.startsWith("{");
  if (looksJson) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new Error("Could not parse JSON key material");
    }
    const bundle = normalizeBundle(parsed);
    if (!bundle) {
      throw new Error("JSON did not contain a recognizable RSA key bundle");
    }
    return bundle;
  }

  const blocks = splitPemBlocks(trimmed);
  if (blocks.length === 0) {
    throw new Error("No PEM blocks found (expected -----BEGIN …-----)");
  }

  const bundle: KeyBundle = { version: 1, label: "imported (PEM)", exportedAt: Date.now() };
  for (const block of blocks) {
    const isPrivate = block.label.includes("PRIVATE KEY");
    const isPublic = block.label.includes("PUBLIC KEY");

    if (isPrivate && !bundle.encryptionPrivate) {
      bundle.encryptionPrivate = await derToJwk(block.der, "private", "RSA-OAEP");
    } else if (isPrivate && !bundle.signingPrivate) {
      bundle.signingPrivate = await derToJwk(block.der, "private", "RSA-PSS");
    } else if (isPublic && !bundle.signingPublic) {
      bundle.signingPublic = await derToJwk(block.der, "public", "RSA-PSS");
    } else if (isPublic && !bundle.encryptionPublic) {
      bundle.encryptionPublic = await derToJwk(block.der, "public", "RSA-OAEP");
    }
  }
  return bundle;
}

/** Turn a parsed bundle into an importable identity (needs a private key). */
export async function bundleToImportedIdentity(
  bundle: KeyBundle,
  format: KeyExportFormat,
): Promise<ImportedIdentity> {
  if (!bundle.encryptionPrivate) {
    throw new Error(
      "Bundle has no encryption private key — one is required to attempt third-party decryption",
    );
  }
  return {
    label: bundle.label || bundle.address || "imported",
    address: bundle.address,
    encryptionPrivateKey: bundle.encryptionPrivate,
    signingPublicKey: bundle.signingPublic,
    fingerprint: await jwkFingerprint(bundle.encryptionPrivate),
    importedAt: Date.now(),
    sourceFormat: format,
  };
}
