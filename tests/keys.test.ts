/**
 * Key management tests — JWK ⇄ PEM conversion and bundle export/import.
 *
 * Env: node (Web Crypto is native in Node 18+).
 */

import { describe, expect, it } from "vitest";

import { generateUserKeyPairs } from "@/lib/crypto/webcrypto";
import { jwkToPem, pemToJwk, splitPemBlocks } from "@/lib/keys/pem";
import {
  buildKeyBundle,
  buildKeyFiles,
  bundleToImportedIdentity,
  parseKeyMaterial,
  normalizeBundle,
} from "@/lib/keys/bundle";
import type { UserProfile } from "@/lib/types";

async function makeProfile(): Promise<UserProfile> {
  const keyPair = await generateUserKeyPairs();
  return {
    id: "test-user",
    displayName: "Test User",
    email: "test@cryptoshield.dev",
    keyPair,
    certificate: {
      x509: {
        serialNumber: "AB",
        subject: "CN=Test User, E=test@cryptoshield.dev",
        issuer: "CN=Test User, E=test@cryptoshield.dev",
        notBefore: 0,
        notAfter: 1,
        publicKeyBase64: "eA==",
        fingerprintSha256: "F".repeat(64),
      },
      pgp: {
        version: 4,
        userId: "Test User <test@cryptoshield.dev>",
        created: 0,
        fingerprint: "A".repeat(40),
        publicKeyArmored:
          "-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----",
        keyFlags: ["encrypt", "sign", "certify"],
      },
    },
    createdAt: Date.now(),
  };
}

describe("PEM conversion", () => {
  it("round-trips an RSA-OAEP public key through PEM", async () => {
    const keys = await generateUserKeyPairs();
    const pem = await jwkToPem(keys.encryption.publicKey, "public", "RSA-OAEP");

    expect(pem).toContain("-----BEGIN PUBLIC KEY-----");
    expect(pem).toContain("-----END PUBLIC KEY-----");

    const back = await pemToJwk(pem, "public", "RSA-OAEP");
    expect(back.n).toBe(keys.encryption.publicKey.n);
    expect(back.e).toBe(keys.encryption.publicKey.e);
  });

  it("round-trips an RSA-OAEP private key as PKCS#8", async () => {
    const keys = await generateUserKeyPairs();
    const pem = await jwkToPem(keys.encryption.privateKey, "private", "RSA-OAEP");

    expect(pem).toContain("-----BEGIN PRIVATE KEY-----");

    const back = await pemToJwk(pem, "private", "RSA-OAEP");
    expect(back.n).toBe(keys.encryption.privateKey.n);
    expect(back.d).toBe(keys.encryption.privateKey.d);
  });

  it("round-trips an RSA-PSS signing private key", async () => {
    const keys = await generateUserKeyPairs();
    const pem = await jwkToPem(keys.signing.privateKey, "private", "RSA-PSS");
    const back = await pemToJwk(pem, "private", "RSA-PSS");
    expect(back.d).toBe(keys.signing.privateKey.d);
  });

  it("wraps PEM at 64 columns", async () => {
    const keys = await generateUserKeyPairs();
    const pem = await jwkToPem(keys.encryption.publicKey, "public", "RSA-OAEP");
    const body = pem
      .split("\n")
      .filter((line) => line && !line.startsWith("-----"));
    expect(body.every((line) => line.length <= 64)).toBe(true);
  });

  it("throws on malformed PEM", async () => {
    await expect(pemToJwk("not a pem", "public", "RSA-OAEP")).rejects.toThrow(/PEM/i);
  });
});

describe("key bundle export", () => {
  it("builds JWK files including private keys when requested", async () => {
    const profile = await makeProfile();
    const files = await buildKeyFiles(profile, "jwk", true);

    expect(files).toHaveLength(5);
    expect(files.some((f) => f.filename.endsWith("-bundle.jwk.json"))).toBe(true);
    expect(files.some((f) => f.filename.includes("encryption-private"))).toBe(true);
    // Filenames are slugged from the address.
    expect(files[0].filename).toContain("test-cryptoshield-dev");
  });

  it("omits private key files by default (public-only export)", async () => {
    const profile = await makeProfile();
    const files = await buildKeyFiles(profile, "jwk", false);
    expect(files).toHaveLength(3);
    expect(files.every((f) => !f.filename.includes("private"))).toBe(true);
  });

  it("builds PEM files with valid armor", async () => {
    const profile = await makeProfile();
    const files = await buildKeyFiles(profile, "pem", true);

    expect(files).toHaveLength(4);
    expect(files.every((f) => f.content.includes("-----BEGIN"))).toBe(true);
    expect(files.some((f) => f.filename.endsWith("-encryption-private.pem"))).toBe(true);
  });
});

describe("key bundle import", () => {
  it("parses a JSON bundle round-trip", async () => {
    const profile = await makeProfile();
    const bundle = buildKeyBundle(profile, true);
    const parsed = await parseKeyMaterial(JSON.stringify(bundle), "jwk");

    expect(parsed.encryptionPrivate?.n).toBe(profile.keyPair.encryption.privateKey.n);
    expect(parsed.signingPrivate?.n).toBe(profile.keyPair.signing.privateKey.n);
  });

  it("accepts a bare private JWK", async () => {
    const keys = await generateUserKeyPairs();
    const parsed = await parseKeyMaterial(
      JSON.stringify(keys.encryption.privateKey),
      "jwk",
    );
    expect(parsed.encryptionPrivate?.n).toBe(keys.encryption.privateKey.n);
  });

  it("accepts a full exported UserProfile", async () => {
    const profile = await makeProfile();
    const parsed = await parseKeyMaterial(JSON.stringify(profile), "jwk");
    expect(parsed.address).toBe("test@cryptoshield.dev");
    expect(parsed.encryptionPrivate?.n).toBe(profile.keyPair.encryption.privateKey.n);
  });

  it("maps a PEM private key to the decryption key", async () => {
    const keys = await generateUserKeyPairs();
    const pem = await jwkToPem(keys.encryption.privateKey, "private", "RSA-OAEP");
    const parsed = await parseKeyMaterial(pem, "pem");

    expect(parsed.encryptionPrivate?.n).toBe(keys.encryption.privateKey.n);
  });

  it("splits multiple PEM blocks", async () => {
    const keys = await generateUserKeyPairs();
    const priv = await jwkToPem(keys.encryption.privateKey, "private", "RSA-OAEP");
    const pub = await jwkToPem(keys.signing.publicKey, "public", "RSA-PSS");
    expect(splitPemBlocks(`${priv}\n${pub}`)).toHaveLength(2);
  });

  it("rejects unparseable material", async () => {
    await expect(parseKeyMaterial("", "jwk")).rejects.toThrow(/Paste or upload/i);
    await expect(parseKeyMaterial("{ not json", "jwk")).rejects.toThrow(/JSON/i);
    await expect(parseKeyMaterial("hello", "pem")).rejects.toThrow(/PEM/i);
    expect(normalizeBundle({ unrelated: true })).toBeNull();
  });

  it("requires a private key to build an importable identity", async () => {
    const profile = await makeProfile();
    const publicOnly = buildKeyBundle(profile, false);
    await expect(bundleToImportedIdentity(publicOnly, "jwk")).rejects.toThrow(
      /private key/i,
    );
  });

  it("builds an imported identity with a fingerprint from a private bundle", async () => {
    const profile = await makeProfile();
    const identity = await bundleToImportedIdentity(buildKeyBundle(profile, true), "jwk");
    expect(identity.fingerprint).toHaveLength(64);
    expect(identity.sourceFormat).toBe("jwk");
  });
});
