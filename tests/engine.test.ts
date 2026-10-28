/**
 * Phase 2 engine: encrypt for a real recipient, decrypt with their private
 * key, and prove that tampering in any of the three places is detected.
 */

import { beforeAll, describe, expect, it } from "vitest";
import {
  base64ToBytes,
  bytesToBase64,
} from "@/lib/crypto";
import { generateIdentityKeyMaterial, type IdentityKeyMaterial } from "@/lib/crypto/identity";
import { decryptMessage, encryptMessage, type SecurePackage } from "@/lib/crypto/engine";
import type { EmailPayload } from "@/lib/types";

const SENDER_EMAIL = "sender@freeshield.test";
const RECIPIENT_EMAIL = "recipient@freeshield.test";
const SUBJECT = "Quarterly key rotation";
const BODY = "<p>Hello <b>Bob</b>, the new keys are live.</p>";

let sender: IdentityKeyMaterial;
let recipient: IdentityKeyMaterial;
let other: IdentityKeyMaterial;
let sealed: SecurePackage;

function storedPayload(pkg: SecurePackage): EmailPayload {
  return {
    id: "msg_1",
    sender: SENDER_EMAIL,
    recipient: RECIPIENT_EMAIL,
    subject: pkg.subject,
    body: "",
    ciphertext: pkg.ciphertext,
    symmetricKey: pkg.encryptedSymmetricKey,
    signature: pkg.signature,
    senderPubKey: sender.publicKeys,
    isSecureMode: true,
    timestamp: pkg.timestamp,
  };
}

beforeAll(async () => {
  [sender, recipient, other] = await Promise.all([
    generateIdentityKeyMaterial(),
    generateIdentityKeyMaterial(),
    generateIdentityKeyMaterial(),
  ]);
  sealed = await encryptMessage({
    sender: {
      email: SENDER_EMAIL,
      publicKeys: sender.publicKeys,
      signingPrivateKey: sender.privateKeys.signing,
    },
    recipient: { email: RECIPIENT_EMAIL, publicKeys: recipient.publicKeys },
    subject: SUBJECT,
    body: BODY,
    timestamp: 1_760_000_000_000,
  });
}, 30_000);

describe("hybrid encryption for persisted mail", () => {
  it("never places the plaintext body in the stored fields", () => {
    expect(sealed.ciphertext).not.toContain("Hello");
    expect(sealed.ciphertext).not.toContain("Bob");
    expect(sealed.encryptedSymmetricKey).not.toContain(BODY);
    expect(sealed.subject).toBe(SUBJECT);
  });

  it("round-trips through the recipient's private key", async () => {
    const outcome = await decryptMessage({
      message: storedPayload(sealed),
      recipientPrivateKeys: recipient.privateKeys,
      senderPublicKeys: sender.publicKeys,
    });

    expect(outcome.verification.status).toBe("verified");
    expect(outcome.payload).toMatchObject({
      sender: SENDER_EMAIL,
      recipient: RECIPIENT_EMAIL,
      subject: SUBJECT,
      body: BODY,
      timestamp: sealed.timestamp,
    });
  });

  it("cannot be unwrapped with a different recipient's key", async () => {
    const outcome = await decryptMessage({
      message: storedPayload(sealed),
      recipientPrivateKeys: other.privateKeys,
      senderPublicKeys: sender.publicKeys,
    });
    expect(outcome.payload).toBeNull();
    expect(outcome.failedStage).toBe("unwrap");
    expect(outcome.verification.status).toBe("spoofed-tampered");
  });

  it("detects a flipped ciphertext byte", async () => {
    const bytes = base64ToBytes(sealed.ciphertext);
    bytes[20] ^= 0xff;
    const outcome = await decryptMessage({
      message: {
        ...storedPayload(sealed),
        ciphertext: bytesToBase64(bytes),
      },
      recipientPrivateKeys: recipient.privateKeys,
      senderPublicKeys: sender.publicKeys,
    });
    expect(outcome.payload).toBeNull();
    expect(outcome.failedStage).toBe("decrypt");
    expect(outcome.verification.status).toBe("spoofed-tampered");
  });

  it("detects an altered signature", async () => {
    const bytes = base64ToBytes(sealed.signature);
    bytes[0] ^= 0x01;
    const outcome = await decryptMessage({
      message: {
        ...storedPayload(sealed),
        signature: bytesToBase64(bytes),
      },
      recipientPrivateKeys: recipient.privateKeys,
      senderPublicKeys: sender.publicKeys,
    });
    expect(outcome.payload).toBeNull();
    expect(outcome.verification.status).toBe("spoofed-tampered");
  });

  it("rejects a row whose subject was edited after signing", async () => {
    const outcome = await decryptMessage({
      message: { ...storedPayload(sealed), subject: "Wire transfer approval" },
      recipientPrivateKeys: recipient.privateKeys,
      senderPublicKeys: sender.publicKeys,
    });
    expect(outcome.payload).toBeNull();
    expect(outcome.verification.reason).toMatch(/metadata/i);
  });

  it("fails closed on an incomplete envelope", async () => {
    const outcome = await decryptMessage({
      message: { ...storedPayload(sealed), signature: null },
      recipientPrivateKeys: recipient.privateKeys,
      senderPublicKeys: sender.publicKeys,
    });
    expect(outcome.verification.status).toBe("spoofed-tampered");
    expect(outcome.failedStage).toBe("payload");
  });
});
