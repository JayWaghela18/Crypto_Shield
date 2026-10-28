/**
 * Server-side demo mailbox.
 *
 * EDUCATION ONLY — the unsafe half of this lab intentionally has no auth and
 * no access control: any caller can read any mailbox by passing `?user=`.
 * That is the vulnerability being demonstrated. Messages are persisted to
 * `.data/cryptoshield-store.json` so a `npm run dev` restart keeps your mail.
 *
 * Stored on globalThis so Next.js dev-mode HMR doesn't wipe the data on every
 * file edit.
 */

import type { EmailPayload } from "@/lib/types";
import { readPersistedStore, updatePersistedStore } from "@/lib/server/persistence";
import { demoSeedEmails } from "@/lib/server/demoSeed";

interface DemoDatabase {
  emails: EmailPayload[];
  hydrated: boolean;
}

const globalStore = globalThis as unknown as { __cryptoshieldDb?: DemoDatabase };

/** Seed mailboxes so every demo profile has something to open. */
function seed(): EmailPayload[] {
  return demoSeedEmails();
}

/** Get (lazily initializing) the shared database. */
function db(): DemoDatabase {
  if (!globalStore.__cryptoshieldDb) {
    const persisted = readPersistedStore();
    globalStore.__cryptoshieldDb = {
      emails: persisted.emails.length > 0 ? persisted.emails : seed(),
      hydrated: true,
    };
    if (persisted.emails.length === 0) {
      updatePersistedStore((store) => {
        store.emails = globalStore.__cryptoshieldDb!.emails;
      });
    }
  }
  return globalStore.__cryptoshieldDb;
}

/** Persist a newly received message. */
export function storeEmail(email: EmailPayload): EmailPayload {
  const database = db();
  database.emails.push(email);
  updatePersistedStore((store) => {
    store.emails = database.emails.slice(-500);
  });
  return email;
}

/** List messages for a mailbox folder (inbox = recipient match, sent = sender match). */
export function listEmails(folder: "inbox" | "sent", address: string): EmailPayload[] {
  const field = folder === "inbox" ? "recipient" : "sender";
  const needle = address.trim().toLowerCase();
  return db()
    .emails.filter((e) => e[field].trim().toLowerCase() === needle)
    .sort((a, b) => b.timestamp - a.timestamp);
}

/** Remove every message addressed to or sent by an address (account reset). */
export function purgeMailbox(address: string): number {
  const needle = address.trim().toLowerCase();
  const database = db();
  const before = database.emails.length;
  database.emails = database.emails.filter(
    (e) =>
      e.sender.trim().toLowerCase() !== needle &&
      e.recipient.trim().toLowerCase() !== needle,
  );
  updatePersistedStore((store) => {
    store.emails = database.emails;
  });
  return before - database.emails.length;
}
