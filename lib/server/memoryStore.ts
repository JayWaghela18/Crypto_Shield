/**
 * Server-side in-memory email database.
 *
 * ⚠ EDUCATIONAL DEMO ONLY — no persistence, no auth, no access control.
 * Every API route reads/writes the same flat list, which is exactly the kind
 * of trust model Phase 1 is demonstrating. Do NOT deploy this publicly.
 *
 * Stored on globalThis so Next.js dev-mode HMR doesn't wipe the data
 * on every file edit.
 */

import type { EmailPayload } from "@/lib/types";

interface DemoDatabase {
  emails: EmailPayload[];
}

const globalStore = globalThis as unknown as { __cryptoshieldDb?: DemoDatabase };

/** Seed mailbox so the UI has content on first load. */
function seed(): EmailPayload[] {
  const now = Date.now();
  return [
    {
      id: crypto.randomUUID(),
      sender: "bob@cryptoshield.dev",
      recipient: "alice@cryptoshield.dev",
      subject: "Workshop schedule for Friday",
      body: "<p>Hey Alice,</p><p>The blockchain workshop starts at <b>10:00 AM</b> in Lab 2. Bring your laptop.</p><p>— Bob</p>",
      ciphertext: null,
      symmetricKey: null,
      signature: null,
      isSecureMode: false,
      timestamp: now - 1000 * 60 * 42,
    },
    {
      id: crypto.randomUUID(),
      sender: "ceo@cryptoshield.dev",
      recipient: "alice@cryptoshield.dev",
      subject: "Quarterly security review",
      body: "<p>Hi team,</p><p>Please review the attached transport findings before Thursday.</p><p>Thanks,<br/>CEO</p>",
      ciphertext: null,
      symmetricKey: null,
      signature: null,
      isSecureMode: false,
      timestamp: now - 1000 * 60 * 60 * 5,
    },
    {
      id: crypto.randomUUID(),
      sender: "alice@cryptoshield.dev",
      recipient: "bob@cryptoshield.dev",
      subject: "Re: Workshop schedule for Friday",
      body: "<p>Works for me — see you at 10.</p>",
      ciphertext: null,
      symmetricKey: null,
      signature: null,
      isSecureMode: false,
      timestamp: now - 1000 * 60 * 30,
    },
  ];
}

/** Get (lazily initializing) the shared database. */
function db(): DemoDatabase {
  if (!globalStore.__cryptoshieldDb) {
    globalStore.__cryptoshieldDb = { emails: seed() };
  }
  return globalStore.__cryptoshieldDb;
}

/**
 * Persist a newly received message.
 * ⚠ No sender validation, no authentication, no recipient authorization —
 * intentional (email spoofing demonstration).
 */
export function storeEmail(email: EmailPayload): EmailPayload {
  db().emails.push(email);
  return email;
}

/** List messages for a mailbox folder (inbox = recipient match, sent = sender match). */
export function listEmails(folder: "inbox" | "sent", address: string): EmailPayload[] {
  const field = folder === "inbox" ? "recipient" : "sender";
  return db()
    .emails.filter((e) => e[field].toLowerCase() === address.toLowerCase())
    .sort((a, b) => b.timestamp - a.timestamp);
}
