/**
 * CRL simulation tests — a revoked certificate must be rejected even when the
 * RSA-PSS signature is mathematically valid, which is the whole point of the
 * revocation demonstration.
 *
 * Env: node (Web Crypto is native in Node 18+).
 */

import { describe, expect, it } from "vitest";

import {
  decryptAndVerify,
  hybridEncrypt,
  jwkFingerprint,
  verifyPayloadSignature,
  type SenderIdentity,
} from "@/lib/crypto";
import { generateUserKeyPairs } from "@/lib/crypto/webcrypto";
import {
  getEntry,
  listRevoked,
  registerBrowserKeys,
  setRevocation,
} from "@/lib/server/keyStore";
import type { DirectoryEntry, EmailPayload, SecurePayload, UserKeyPair } from "@/lib/types";

const PAYLOAD: SecurePayload = {
  sender: "alice@cryptoshield.dev",
  recipient: "bob@cryptoshield.dev",
  subject: "Revocation test",
  body: "<p>signed and encrypted</p>",
  timestamp: 1_700_000_000_000,
};

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

async function directoryFor(
  address: string,
  keys: UserKeyPair,
  revoked = false,
): Promise<DirectoryEntry> {
  return {
    address,
    encryptionPub: keys.encryption.publicKey,
    signingPub: keys.signing.publicKey,
    fingerprint: await jwkFingerprint(keys.signing.publicKey),
    source: "browser",
    revoked,
    ...(revoked ? { revokedAt: Date.now(), revokeReason: "keyCompromise (demo CRL)" } : {}),
  };
}

function toEmail(
  envelope: Awaited<ReturnType<typeof hybridEncrypt>>,
  payload: SecurePayload,
): EmailPayload {
  return {
    id: "revocation-test",
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

describe("certificate revocation (CRL)", () => {
  it("still decrypts the message but rejects a revoked certificate", async () => {
    const sender = await generateUserKeyPairs();
    const recipient = await generateUserKeyPairs();

    const envelope = await hybridEncrypt(
      PAYLOAD,
      recipient.encryption.publicKey,
      senderIdentity(PAYLOAD.sender, sender),
    );

    const outcome = await decryptAndVerify(
      toEmail(envelope, PAYLOAD),
      recipient.encryption.privateKey,
      await directoryFor(PAYLOAD.sender, sender, /* revoked */ true),
    );

    // The crypto all works — decryption succeeded and the body is available.
    expect(outcome.payload).toEqual(PAYLOAD);
    // …but the certificate is revoked, so verification must reject it.
    expect(outcome.verification.status).toBe("revoked");
    expect(outcome.verification.revoked).toBe(true);
    expect(outcome.verification.reason).toMatch(/REVOKED/i);
    expect(outcome.verification.reason).toMatch(/mathematically valid/i);
  });

  it("accepts the SAME message when the certificate is not revoked", async () => {
    const sender = await generateUserKeyPairs();
    const recipient = await generateUserKeyPairs();

    const envelope = await hybridEncrypt(
      PAYLOAD,
      recipient.encryption.publicKey,
      senderIdentity(PAYLOAD.sender, sender),
    );

    const outcome = await decryptAndVerify(
      toEmail(envelope, PAYLOAD),
      recipient.encryption.privateKey,
      await directoryFor(PAYLOAD.sender, sender, false),
    );

    expect(outcome.verification.status).toBe("verified");
    expect(outcome.payload).toEqual(PAYLOAD);
  });

  it("verifyPayloadSignature reports revoked after a valid signature check", async () => {
    const sender = await generateUserKeyPairs();
    const recipient = await generateUserKeyPairs();

    const envelope = await hybridEncrypt(
      PAYLOAD,
      recipient.encryption.publicKey,
      senderIdentity(PAYLOAD.sender, sender),
    );

    const revoked = await verifyPayloadSignature(
      PAYLOAD,
      envelope.signature,
      envelope.senderPubKey,
      await directoryFor(PAYLOAD.sender, sender, true),
    );
    expect(revoked.status).toBe("revoked");

    const valid = await verifyPayloadSignature(
      PAYLOAD,
      envelope.signature,
      envelope.senderPubKey,
      await directoryFor(PAYLOAD.sender, sender, false),
    );
    expect(valid.status).toBe("verified");
  });
});

describe("keyStore revocation state", () => {
  it("revokes, lists and reinstates a registered certificate", async () => {
    const keys = await generateUserKeyPairs();
    await registerBrowserKeys(
      "carol@cryptoshield.dev",
      keys.encryption.publicKey,
      keys.signing.publicKey,
    );

    const before = await getEntry("carol@cryptoshield.dev");
    expect(before?.revoked).toBe(false);

    const revoked = await setRevocation("carol@cryptoshield.dev", true, "test reason");
    expect(revoked?.revoked).toBe(true);
    expect(revoked?.revokeReason).toBe("test reason");

    expect(listRevoked().map((c) => c.address)).toContain("carol@cryptoshield.dev");

    const reinstated = await setRevocation("carol@cryptoshield.dev", false);
    expect(reinstated?.revoked).toBe(false);
    expect(listRevoked().map((c) => c.address)).not.toContain("carol@cryptoshield.dev");
  });

  it("returns null when revoking an unknown, non-demo address", async () => {
    await expect(
      setRevocation("nobody@nowhere.example", true),
    ).resolves.toBeNull();
  });

  it("can revoke a server-held demo identity", async () => {
    const entry = await setRevocation("ceo@cryptoshield.dev", true, "left the company");
    expect(entry?.source).toBe("demo");
    expect(entry?.revoked).toBe(true);
    await setRevocation("ceo@cryptoshield.dev", false); // clean up
  });
});
