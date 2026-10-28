/**
 * Shared server-side mail helpers.
 *
 * The API never returns a `User` row as-is: only public fields and public key
 * material leave the server. Secure bodies are returned as `ciphertext`
 * (never copied into `body`), so the UI cannot accidentally render them as
 * plaintext.
 */

import type { Prisma } from "@prisma/client";
import { parsePublicKeyBundle } from "@/lib/auth/keyMaterial";
import type { MailboxMessage, SenderPublicKeys } from "@/lib/types";

export const MAIL_PARTY_SELECT = {
  id: true,
  name: true,
  email: true,
  publicKeyJwk: true,
} satisfies Prisma.UserSelect;

export const MAIL_INCLUDE = {
  sender: { select: MAIL_PARTY_SELECT },
  recipient: { select: MAIL_PARTY_SELECT },
} satisfies Prisma.EmailInclude;

interface StoredParty {
  id: string;
  name: string;
  email: string;
  publicKeyJwk: string;
}

export interface StoredMailRow {
  id: string;
  senderId: string;
  recipientId: string;
  subject: string;
  body: string;
  encryptedSymmetricKey: string | null;
  signature: string | null;
  isSecureMode: boolean;
  isTampered: boolean;
  createdAt: Date;
  sender: StoredParty;
  recipient: StoredParty;
}

/** Parse a stored public key bundle defensively (corrupt rows fail closed). */
export function storedPublicKeys(publicKeyJwk: string): SenderPublicKeys | null {
  try {
    return parsePublicKeyBundle(publicKeyJwk);
  } catch {
    return null;
  }
}

/**
 * Map a database row to the client message shape.
 *
 * Secure: `body` is blank and the ciphertext lives in `ciphertext`; the
 * sender's DB-registered public keys accompany the message for verification.
 * Unsafe: the plaintext HTML is returned as-is.
 *
 * `folder` decides `sentByMe`: a message can appear in both folders (the local
 * account mailing itself), and only the Sent copy is the unreadable one.
 */
export function serializeMail(
  row: StoredMailRow,
  viewerId: string,
  folder: "inbox" | "sent" = "inbox",
): MailboxMessage {
  const secure = row.isSecureMode;
  const senderKeys = secure ? storedPublicKeys(row.sender.publicKeyJwk) : null;

  return {
    id: row.id,
    sender: row.sender.email,
    recipient: row.recipient.email,
    senderName: row.sender.name,
    recipientName: row.recipient.name,
    subject: row.subject,
    body: secure ? "" : row.body,
    ciphertext: secure ? row.body : null,
    symmetricKey: secure ? row.encryptedSymmetricKey : null,
    signature: secure ? row.signature : null,
    senderPubKey: senderKeys,
    isSecureMode: secure,
    isTampered: row.isTampered,
    timestamp: row.createdAt.getTime(),
    sentByMe: folder === "sent" && row.senderId === viewerId,
  };
}
