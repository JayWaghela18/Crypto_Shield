/**
 * /api/email — CryptoShield email engine.
 *
 * SEND   POST /api/email            — accepts a raw or secure message.
 * RECEIVE GET /api/email?mailbox=&user= — returns a folder's messages.
 *
 * ⚠⚠ UNSAFE MODE (Phase 1) — do not copy into real applications ⚠⚠
 *  1. EMAIL SPOOFING: `sender` is stored verbatim from the request body.
 *     There is no session, no authentication, and no check that the sender
 *     owns the address — anyone can claim to be anyone.
 *  2. NO ENCRYPTION: unsafe-mode bodies travel and are stored as raw HTML;
 *     they are rendered unsanitized by the client (Stored XSS demo).
 *  3. NO AUTHORIZATION: any caller can read any mailbox by passing ?user=.
 *
 * ✅ SECURE MODE (Phase 2): the server only relays the opaque hybrid
 *    envelope `{ ciphertext, symmetricKey, signature, senderPubKey }`.
 *    It holds no keys and cannot decrypt or forge these messages —
 *    identity is established client-side against the /api/keys directory.
 *    Decryption, signature verification and DOMPurify sanitization all
 *    happen on the receiving client.
 */

import { NextResponse } from "next/server";
import type { EmailDraft, EmailPayload, SenderPublicKeys } from "@/lib/types";
import { listEmails, storeEmail } from "@/lib/server/memoryStore";

/** Fields the secure engine may attach to a send (opaque crypto material). */
interface SecurePackageFields {
  isSecureMode?: boolean;
  ciphertext?: string | null;
  symmetricKey?: string | null;
  signature?: string | null;
  senderPubKey?: SenderPublicKeys | null;
}

/** SEND — store a message (plaintext in unsafe mode, envelope in secure mode). */
export async function POST(request: Request) {
  const draft = (await request.json()) as Partial<EmailDraft> & SecurePackageFields;

  if (!draft.recipient) {
    return NextResponse.json({ error: "recipient is required" }, { status: 400 });
  }

  const isSecure = draft.isSecureMode === true;
  // In secure mode the payload must actually be encrypted — reject fakes.
  if (isSecure && (!draft.ciphertext || !draft.symmetricKey || !draft.signature)) {
    return NextResponse.json(
      { error: "secure message missing ciphertext / symmetricKey / signature" },
      { status: 400 },
    );
  }
  if (!isSecure && !draft.body) {
    return NextResponse.json({ error: "body is required" }, { status: 400 });
  }

  const email: EmailPayload = {
    id: crypto.randomUUID(),
    // ⚠ SPOOFABLE: taken verbatim — no verification that the sender owns
    // this address. Anti-spoofing ONLY exists in secure mode via signatures.
    sender: draft.sender?.trim() || "spoofed@unverified.example",
    recipient: draft.recipient.trim(),
    subject: draft.subject?.trim() || (isSecure ? "(end-to-end encrypted)" : "(no subject)"),
    // Secure mode: content lives inside the ciphertext only; the server copy
    // of the body stays empty (the server has no keys to read it — by design).
    body: isSecure ? "" : draft.body ?? "",
    ciphertext: draft.ciphertext ?? null,
    symmetricKey: draft.symmetricKey ?? null,
    signature: draft.signature ?? null,
    senderPubKey: draft.senderPubKey ?? null,
    isSecureMode: isSecure,
    timestamp: Date.now(),
  };

  storeEmail(email);
  return NextResponse.json(email, { status: 201 });
}

/** RECEIVE — return a mailbox folder (inbox or sent) as JSON. */
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const mailbox = searchParams.get("mailbox") === "sent" ? "sent" : "inbox";
  const user = searchParams.get("user") ?? "";

  if (!user) {
    return NextResponse.json({ error: "user query param is required" }, { status: 400 });
  }

  const emails = listEmails(mailbox, user);
  return NextResponse.json(emails, {
    headers: { "Cache-Control": "no-store" },
  });
}
