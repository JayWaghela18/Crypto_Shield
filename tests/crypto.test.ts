/**
 * CryptoShield — cryptographic engine unit tests.
 *
 * Exercises the real modules the app ships (`lib/crypto.ts`,
 * `lib/crypto/webcrypto.ts`) against the platform Web Crypto API. Nothing here
 * is mocked: keys are genuinely generated, messages genuinely encrypted and
 * signed, and tampering genuinely detected.
 *
 * Env: `node` (Web Crypto is native in Node 18+; see vitest.config.ts).
 */

import { describe, expect, it } from "vitest";

import {
  canonicalPayloadBytes,
  decryptAndVerify,
  hybridEncrypt,
  jwkFingerprint,
  sha256Hex,
  verifyPayloadSignature,
  type SenderIdentity,
} from "@/lib/crypto";
import {
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  generateUserKeyPairs,
} from "@/lib/crypto/webcrypto";
import { tamperCiphertext } from "@/lib/attacks";
import type {
  DirectoryEntry,
  EmailPayload,
  SecurePayload,
  UserKeyPair,
} from "@/lib/types";

/* ------------------------------------------------------------------ */
/* Fixtures / helpers                                                  */
/* ------------------------------------------------------------------ */

const PLAINTEXT: SecurePayload = {
  sender: "alice@cryptoshield.dev",
  recipient: "bob@cryptoshield.dev",
  subject: "Q3 transfer authorization",
  body: "<p>Please transfer $100 to ACCT-12345.</p>",
  timestamp: 1_700_000_000_000,
};

/** A directory entry that publishes a user's public keys (trust root). */
async function makeDirectory(
  address: string,
  keys: UserKeyPair,
): Promise<DirectoryEntry> {
  return {
    address,
    encryptionPub: keys.encryption.publicKey,
    signingPub: keys.signing.publicKey,
    fingerprint: await jwkFingerprint(keys.signing.publicKey),
    source: "browser",
  };
}

/** Sender identity used while packaging a secure message. */
function senderIdentity(address: string, keys: UserKeyPair): SenderIdentity {
  return {
    address,
    publicKey: {
      encryption: keys.encryption.publicKey,
      signing: keys.signing.publicKey,
    },
    signingPriv: keys.signing.privateKey,
  };
}

/** Rebuild the received `EmailPayload` a client would read off the wire. */
function envelopeToEmail(
  envelope: Awaited<ReturnType<typeof hybridEncrypt>>,
  payload: SecurePayload,
): EmailPayload {
  return {
    id: "test-message-id",
    sender: payload.sender,
    recipient: payload.recipient,
    subject: "(end-to-end encrypted)",
    body: "",
    ciphertext: envelope.payloadCiphertext,
    symmetricKey: envelope.encryptedSymmetricKey,
    signature: envelope.signature,
    senderPubKey: envelope.senderPubKey,
    isSecureMode: true,
    timestamp: payload.timestamp,
  };
}

/* ------------------------------------------------------------------ */
/* 1. Key pair generation                                              */
/* ------------------------------------------------------------------ */

describe("key pair generation", () => {
  it("generates an RSA-OAEP encryption pair (2048-bit, SHA-256)", async () => {
    const pair = await generateEncryptionKeyPair();

    expect(pair.algorithm).toBe("RSA-OAEP-256");
    expect(pair.modulusLength).toBe(2048);
    expect(pair.publicKey.kty).toBe("RSA");
    expect(pair.publicKey.n).toBeTruthy();
    expect(pair.publicKey.e).toBeTruthy();
    // Private material is present but must never be sent anywhere.
    expect(pair.privateKey.d).toBeTruthy();
  });

  it("generates an RSA-PSS signing pair (2048-bit, SHA-256)", async () => {
    const pair = await generateSigningKeyPair();

    // NOTE: CryptoShield signs with RSA-PSS (salted), not RSASSA-PKCS1-v1_5.
    // Both are RSA / SHA-256, but PSS is the modern, randomized scheme.
    expect(pair.algorithm).toBe("RSA-PSS-256");
    expect(pair.modulusLength).toBe(2048);
    expect(pair.publicKey.kty).toBe("RSA");
    expect(pair.privateKey.d).toBeTruthy();
  });

  it("produces a fresh, non-repeating key pair on each call", async () => {
    const [a, b] = await Promise.all([
      generateSigningKeyPair(),
      generateSigningKeyPair(),
    ]);
    expect(a.publicKey.n).not.toBe(b.publicKey.n);
  });

  it("generateUserKeyPairs returns distinct encryption and signing pairs", async () => {
    const keys = await generateUserKeyPairs();

    expect(keys.encryption.algorithm).toBe("RSA-OAEP-256");
    expect(keys.signing.algorithm).toBe("RSA-PSS-256");
    // The two pairs must not be the same key material.
    expect(keys.encryption.publicKey.n).not.toBe(keys.signing.publicKey.n);
  });

  it("signs/verifies with RSA-PSS and keeps RSASSA-PKCS1-v1_5 separate", async () => {
    // Documents the deliberate algorithm choice: the app's signing pair is
    // RSA-PSS, and a PKCS1-v1_5 signature is NOT interchangeable with it.
    const pss = await generateSigningKeyPair();

    const pssRaw = await crypto.subtle.importKey(
      "jwk",
      stripMeta(pss.privateKey),
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const pssPub = await crypto.subtle.importKey(
      "jwk",
      stripMeta(pss.publicKey),
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const data = new TextEncoder().encode("canonical payload");
    const sig = await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      pssRaw,
      data,
    );
    await expect(
      crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pssPub, sig, data),
    ).resolves.toBe(true);

    // The platform also supports RSASSA-PKCS1-v1_5 (requested coverage), but
    // verifying a PKCS1 signature with the PSS public key must fail.
    const pkcs1 = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const pkcs1Sig = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      pkcs1.privateKey,
      data,
    );
    await expect(
      crypto.subtle.verify("RSASSA-PKCS1-v1_5", pkcs1.publicKey, pkcs1Sig, data),
    ).resolves.toBe(true);
    await expect(
      crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pssPub, pkcs1Sig, data),
    ).resolves.toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* 2. AES-256-GCM round trip                                           */
/* ------------------------------------------------------------------ */

describe("AES-256-GCM hybrid round trip", () => {
  it("decrypts an encrypted payload back to the exact original bytes", async () => {
    const recipient = await generateUserKeyPairs();
    const sender = await generateUserKeyPairs();

    const envelope = await hybridEncrypt(
      PLAINTEXT,
      recipient.encryption.publicKey,
      senderIdentity(PLAINTEXT.sender, sender),
    );

    const directory = await makeDirectory(PLAINTEXT.sender, sender);
    const outcome = await decryptAndVerify(
      envelopeToEmail(envelope, PLAINTEXT),
      recipient.encryption.privateKey,
      directory,
    );

    expect(outcome.verification.status).toBe("verified");
    expect(outcome.payload).toEqual(PLAINTEXT);
  });

  it("never places the plaintext on the wire", async () => {
    const recipient = await generateUserKeyPairs();
    const sender = await generateUserKeyPairs();

    const envelope = await hybridEncrypt(
      PLAINTEXT,
      recipient.encryption.publicKey,
      senderIdentity(PLAINTEXT.sender, sender),
    );

    const wire = JSON.stringify(envelope);
    expect(wire).not.toContain("transfer");
    expect(wire).not.toContain("ACCT-12345");
    expect(wire).not.toContain(PLAINTEXT.body);
    expect(envelope.payloadCiphertext).not.toBe(PLAINTEXT.body);
  });

  it("uses a fresh random IV per message (ciphertexts differ)", async () => {
    const recipient = await generateUserKeyPairs();
    const sender = await generateUserKeyPairs();
    const identity = senderIdentity(PLAINTEXT.sender, sender);

    const [a, b] = await Promise.all([
      hybridEncrypt(PLAINTEXT, recipient.encryption.publicKey, identity),
      hybridEncrypt(PLAINTEXT, recipient.encryption.publicKey, identity),
    ]);

    expect(a.payloadCiphertext).not.toBe(b.payloadCiphertext);
  });

  it("canonical payload bytes are deterministic and order-independent", async () => {
    const reordered: SecurePayload = {
      timestamp: PLAINTEXT.timestamp,
      body: PLAINTEXT.body,
      subject: PLAINTEXT.subject,
      recipient: PLAINTEXT.recipient,
      sender: PLAINTEXT.sender,
    };
    expect(await sha256Hex(canonicalPayloadBytes(PLAINTEXT))).toBe(
      await sha256Hex(canonicalPayloadBytes(reordered)),
    );
  });
});

/* ------------------------------------------------------------------ */
/* 3. Tamper detection                                                 */
/* ------------------------------------------------------------------ */

describe("tamper detection", () => {
  it("flipping ONE ciphertext character fails decryption with an explicit error", async () => {
    const recipient = await generateUserKeyPairs();
    const sender = await generateUserKeyPairs();
    const identity = senderIdentity(PLAINTEXT.sender, sender);

    const envelope = await hybridEncrypt(
      PLAINTEXT,
      recipient.encryption.publicKey,
      identity,
    );
    const tampered = {
      ...envelope,
      payloadCiphertext: tamperCiphertext(envelope.payloadCiphertext),
    };

    const outcome = await decryptAndVerify(
      envelopeToEmail(tampered, PLAINTEXT),
      recipient.encryption.privateKey,
      await makeDirectory(PLAINTEXT.sender, sender),
    );

    expect(tampered.payloadCiphertext).not.toBe(envelope.payloadCiphertext);
    expect(outcome.payload).toBeNull();
    expect(outcome.failedStage).toBe("decrypt");
    expect(outcome.verification.status).toBe("spoofed-tampered");
    expect(outcome.verification.reason).toMatch(/Tampering Detected/i);
  });

  it("the raw AES-GCM primitive rejects a tampered ciphertext", async () => {
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        new TextEncoder().encode("transfer $100"),
      ),
    );
    ct[0] ^= 0x01; // flip a single bit

    await expect(
      crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct),
    ).rejects.toThrow();
  });

  it("flipping ONE signature character fails signature verification explicitly", async () => {
    const recipient = await generateUserKeyPairs();
    const sender = await generateUserKeyPairs();
    const identity = senderIdentity(PLAINTEXT.sender, sender);

    const envelope = await hybridEncrypt(
      PLAINTEXT,
      recipient.encryption.publicKey,
      identity,
    );
    const tampered = {
      ...envelope,
      signature: tamperCiphertext(envelope.signature),
    };

    const outcome = await decryptAndVerify(
      envelopeToEmail(tampered, PLAINTEXT),
      recipient.encryption.privateKey,
      await makeDirectory(PLAINTEXT.sender, sender),
    );

    // Decryption still succeeds (the ciphertext is untouched) but the
    // signature over the canonical payload no longer verifies.
    expect(outcome.verification.status).toBe("spoofed-tampered");
    expect(outcome.verification.reason).toMatch(/signature INVALID/i);
  });

  it("mutating the payload after signing invalidates the signature", async () => {
    const sender = await generateUserKeyPairs();
    const identity = senderIdentity(PLAINTEXT.sender, sender);
    const recipient = await generateUserKeyPairs();

    const envelope = await hybridEncrypt(
      PLAINTEXT,
      recipient.encryption.publicKey,
      identity,
    );

    const altered: SecurePayload = { ...PLAINTEXT, body: "transfer $900 instead" };
    const result = await verifyPayloadSignature(
      altered,
      envelope.signature,
      envelope.senderPubKey,
      await makeDirectory(PLAINTEXT.sender, sender),
    );

    expect(result.status).toBe("spoofed-tampered");
    expect(result.reason).toMatch(/signature INVALID/i);
  });

  it("reports tampering as a failure outcome rather than throwing", async () => {
    const recipient = await generateUserKeyPairs();
    const sender = await generateUserKeyPairs();

    const envelope = await hybridEncrypt(
      PLAINTEXT,
      recipient.encryption.publicKey,
      senderIdentity(PLAINTEXT.sender, sender),
    );
    const tampered = {
      ...envelope,
      payloadCiphertext: tamperCiphertext(envelope.payloadCiphertext),
    };

    await expect(
      decryptAndVerify(
        envelopeToEmail(tampered, PLAINTEXT),
        recipient.encryption.privateKey,
        await makeDirectory(PLAINTEXT.sender, sender),
      ),
    ).resolves.toBeDefined();
  });
});

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/** Remove JWK fields some engines reject when `importKey`-ing. */
function stripMeta(jwk: JsonWebKey): JsonWebKey {
  const copy = { ...jwk };
  delete copy.alg;
  delete copy.use;
  delete copy.key_ops;
  return copy;
}
