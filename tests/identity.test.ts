/**
 * Identity key material: real Web Crypto key generation, public-key
 * validation, and the password-encrypted private-key backup.
 */

import { beforeAll, describe, expect, it } from "vitest";
import {
  base64ToBytes,
  bytesToBase64,
  decryptPrivateKeys,
  encryptPrivateKeys,
  generateIdentityKeyMaterial,
  type IdentityKeyMaterial,
} from "@/lib/crypto/identity";
import {
  assertImportablePublicKeys,
  fingerprintPublicKey,
  fingerprintStoredIdentity,
  KeyMaterialError,
  parseEncryptedPrivateKeyBackup,
  parsePublicKeyBundle,
  serialisePublicKeyBundle,
} from "@/lib/auth/keyMaterial";

const PASSWORD = "correct horse battery staple";

let material: IdentityKeyMaterial;

beforeAll(async () => {
  material = await generateIdentityKeyMaterial();
}, 20_000);

describe("identity generation", () => {
  it("generates RSA public keys with no private fields", () => {
    expect(material.publicKeys.encryption.kty).toBe("RSA");
    expect(material.publicKeys.signing.kty).toBe("RSA");
    expect(material.publicKeys.encryption.d).toBeUndefined();
    expect(material.publicKeys.signing.d).toBeUndefined();
    expect(material.publicKeys.encryption.alg).toBe("RSA-OAEP-256");
    expect(material.publicKeys.signing.alg).toBe("PS256");
  });

  it("keeps the private exponents only in the private half", () => {
    expect(typeof material.privateKeys.encryption.d).toBe("string");
    expect(typeof material.privateKeys.signing.d).toBe("string");
  });

  it("produces keys the mail engine can actually import", async () => {
    await expect(
      assertImportablePublicKeys({
        encryption: material.publicKeys.encryption,
        signing: material.publicKeys.signing,
      }),
    ).resolves.toBeUndefined();
  });
});

describe("public key validation", () => {
  it("accepts a generated bundle and strips non-public fields", () => {
    const bundle = parsePublicKeyBundle({
      encryption: material.publicKeys.encryption,
      signing: material.publicKeys.signing,
    });
    expect(bundle.encryption).toMatchObject({ kty: "RSA", alg: "RSA-OAEP-256" });
    expect(bundle.signing).toMatchObject({ kty: "RSA", alg: "PS256" });
  });

  it("accepts the persisted { version, encryption, signing } string", () => {
    const stored = serialisePublicKeyBundle(material.publicKeys);
    const bundle = parsePublicKeyBundle(stored);
    expect(bundle.signing.n).toBe(material.publicKeys.signing.n);
  });

  it("rejects a bundle that smuggles in a private key", () => {
    expect(() =>
      parsePublicKeyBundle({
        encryption: material.publicKeys.encryption,
        signing: { ...material.publicKeys.signing, d: "PRIVATE" },
      }),
    ).toThrow(KeyMaterialError);
  });

  it("rejects non-RSA material", () => {
    expect(() =>
      parsePublicKeyBundle({
        encryption: { kty: "EC", crv: "P-256", x: "a", y: "b" },
        signing: material.publicKeys.signing,
      }),
    ).toThrow(/RSA/);
  });

  it("rejects an algorithm mismatch", () => {
    expect(() =>
      parsePublicKeyBundle({
        encryption: { ...material.publicKeys.encryption, alg: "RSA-PSS" },
        signing: material.publicKeys.signing,
      }),
    ).toThrow(/expected "RSA-OAEP-256"/);
  });

  it("rejects a partial bundle", () => {
    expect(() => parsePublicKeyBundle({ signing: material.publicKeys.signing })).toThrow(
      /encryption/,
    );
  });

  it("fingerprints deterministically as 64 uppercase hex characters", async () => {
    const first = await fingerprintPublicKey(material.publicKeys.signing);
    const second = await fingerprintPublicKey(material.publicKeys.signing);
    const stored = await fingerprintStoredIdentity(
      serialisePublicKeyBundle(material.publicKeys),
    );
    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9A-F]{64}$/);
    expect(stored).toBe(first);
  });
});

describe("encrypted private-key backup", () => {
  it("round-trips the private keys with the correct password", async () => {
    const backup = await encryptPrivateKeys(material.privateKeys, PASSWORD, 100_000);
    const restored = await decryptPrivateKeys(backup, PASSWORD);
    expect(restored.encryption).toEqual(material.privateKeys.encryption);
    expect(restored.signing).toEqual(material.privateKeys.signing);
  }, 20_000);

  it("never stores the private exponent in ciphertext", async () => {
    const backup = await encryptPrivateKeys(material.privateKeys, PASSWORD, 100_000);
    expect(backup.ciphertext).not.toContain(material.privateKeys.signing.d!);
  }, 20_000);

  it("fails closed on a wrong password", async () => {
    const backup = await encryptPrivateKeys(material.privateKeys, PASSWORD, 100_000);
    await expect(decryptPrivateKeys(backup, "wrong password")).rejects.toThrow(
      /wrong password|corrupted/i,
    );
  }, 20_000);

  it("detects ciphertext tampering", async () => {
    const backup = await encryptPrivateKeys(material.privateKeys, PASSWORD, 100_000);
    const bytes = base64ToBytes(backup.ciphertext);
    bytes[0] ^= 0xff;
    await expect(
      decryptPrivateKeys({ ...backup, ciphertext: bytesToBase64(bytes) }, PASSWORD),
    ).rejects.toThrow(/wrong password|corrupted/i);
  }, 20_000);

  it("validates the backup envelope server-side", async () => {
    const backup = await encryptPrivateKeys(material.privateKeys, PASSWORD, 100_000);
    expect(parseEncryptedPrivateKeyBackup(JSON.stringify(backup))).toMatchObject({
      v: 1,
      kdf: "PBKDF2-SHA256",
      cipher: "AES-256-GCM",
      iterations: 100_000,
    });
  }, 20_000);

  it("rejects a weak KDF iteration count and an invalid IV", () => {
    expect(() =>
      parseEncryptedPrivateKeyBackup({
        v: 1,
        kdf: "PBKDF2-SHA256",
        cipher: "AES-256-GCM",
        iterations: 1_000,
        salt: bytesToBase64(new Uint8Array(16)),
        iv: bytesToBase64(new Uint8Array(12)),
        ciphertext: bytesToBase64(new Uint8Array(48)),
      }),
    ).toThrow(/iterations/);

    expect(() =>
      parseEncryptedPrivateKeyBackup({
        v: 1,
        kdf: "PBKDF2-SHA256",
        cipher: "AES-256-GCM",
        iterations: 210_000,
        salt: bytesToBase64(new Uint8Array(16)),
        iv: bytesToBase64(new Uint8Array(8)),
        ciphertext: bytesToBase64(new Uint8Array(48)),
      }),
    ).toThrow(/IV must be 12 bytes/);
  });
});
