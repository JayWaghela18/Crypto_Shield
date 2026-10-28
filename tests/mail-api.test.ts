/**
 * Mail API boundary tests: request validation and the guarantee that secure
 * ciphertext is never serialized as readable `body` text.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { generateIdentityKeyMaterial, type IdentityKeyMaterial } from "@/lib/crypto/identity";
import { serializeMail, type StoredMailRow } from "@/lib/server/mail";
import { sendMailSchema } from "@/lib/validation/mail";

let identity: IdentityKeyMaterial;

beforeAll(async () => {
  identity = await generateIdentityKeyMaterial();
}, 20_000);

const base = {
  recipient: "  Bob@Example.COM ",
  subject: "  Hello  ",
  isSecureMode: false,
  body: "<p>plain text</p>",
};

describe("sendMailSchema", () => {
  it("normalizes the recipient and trims the subject", () => {
    const parsed = sendMailSchema.parse(base);
    expect(parsed.recipient).toBe("bob@example.com");
    expect(parsed.subject).toBe("Hello");
  });

  it("accepts safe-mode plaintext without crypto fields", () => {
    expect(sendMailSchema.safeParse(base).success).toBe(true);
  });

  it("requires a wrapped key, signature and base64 body in secure mode", () => {
    const result = sendMailSchema.safeParse({ ...base, isSecureMode: true });
    expect(result.success).toBe(false);
    if (!result.success) {
      const paths = result.error.issues.map((issue) => issue.path.join("."));
      expect(paths).toContain("encryptedSymmetricKey");
      expect(paths).toContain("signature");
      expect(paths).toContain("body");
    }
  });

  it("rejects malformed envelope fields", () => {
    const result = sendMailSchema.safeParse({
      ...base,
      isSecureMode: true,
      body: "not base64 at all !!!",
      encryptedSymmetricKey: "<script>",
      signature: "not base64",
    });
    expect(result.success).toBe(false);
  });

  it("rejects an unregistered-looking recipient and oversized bodies", () => {
    expect(sendMailSchema.safeParse({ ...base, recipient: "not-an-email" }).success).toBe(
      false,
    );
    expect(
      sendMailSchema.safeParse({ ...base, body: "x".repeat(100_001) }).success,
    ).toBe(false);
  });
});

function row(overrides: Partial<StoredMailRow> = {}): StoredMailRow {
  return {
    id: "mail_1",
    senderId: "user_sender",
    recipientId: "user_recipient",
    subject: "Subject",
    body: "<p>secret</p>",
    encryptedSymmetricKey: "d3JhcHBlZA==",
    signature: "c2lnbmF0dXJl",
    isSecureMode: false,
    isTampered: false,
    createdAt: new Date("2026-10-21T10:00:00.000Z"),
    sender: {
      id: "user_sender",
      name: "Ada",
      email: "ada@freeshield.test",
      publicKeyJwk: JSON.stringify(identity.publicKeys),
    },
    recipient: {
      id: "user_recipient",
      name: "Bob",
      email: "bob@freeshield.test",
      publicKeyJwk: JSON.stringify(identity.publicKeys),
    },
    ...overrides,
  };
}

describe("serializeMail", () => {
  it("returns plaintext for unsafe rows", () => {
    const message = serializeMail(row(), "user_recipient");
    expect(message.body).toBe("<p>secret</p>");
    expect(message.ciphertext).toBeNull();
    expect(message.senderName).toBe("Ada");
    expect(message.sentByMe).toBe(false);
  });

  it("never exposes secure ciphertext as `body`", () => {
    const message = serializeMail(
      row({
        isSecureMode: true,
        body: "YmFzZTY0Y2lwaGVydGV4dA==",
      }),
      "user_recipient",
    );
    expect(message.body).toBe("");
    expect(message.ciphertext).toBe("YmFzZTY0Y2lwaGVydGV4dA==");
    expect(message.symmetricKey).toBe("d3JhcHBlZA==");
    expect(message.signature).toBe("c2lnbmF0dXJl");
    expect(message.senderPubKey?.signing.n).toBe(identity.publicKeys.signing.n);
    expect(message.senderPubKey?.encryption.n).toBe(identity.publicKeys.encryption.n);
  });

  it("marks rows in the Sent folder as the viewer's own", () => {
    expect(serializeMail(row(), "user_sender", "sent").sentByMe).toBe(true);
    expect(serializeMail(row(), "user_sender", "inbox").sentByMe).toBe(false);
  });

  it("does not include a private-key backup in the response", () => {
    const message = serializeMail(row(), "user_sender") as unknown as Record<
      string,
      unknown
    >;
    expect(message).not.toHaveProperty("encryptedPrivateKey");
    expect(message).not.toHaveProperty("passwordHash");
  });
});
