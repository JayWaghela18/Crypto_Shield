/**
 * Seed mailbox content shared by BOTH deployments:
 *   • the Node server (`lib/server/memoryStore.ts`) seeds these messages when
 *     its persisted store is empty;
 *   • the static GitHub Pages relay (`lib/api/staticRelay.ts`) seeds them into
 *     localStorage on a first visit, so the exported demo is not an empty inbox.
 *
 * Deliberately free of Node-only imports (no `node:fs`) — this module is safe
 * to bundle into the browser.
 */

import type { EmailPayload } from "@/lib/types";

/** Seed mailboxes so every demo profile has something to open. */
export function demoSeedEmails(): EmailPayload[] {
  const now = Date.now();

  const mail = (
    sender: string,
    recipient: string,
    subject: string,
    body: string,
    minutesAgo: number,
  ): EmailPayload => ({
    id: crypto.randomUUID(),
    sender,
    recipient,
    subject,
    body,
    ciphertext: null,
    symmetricKey: null,
    signature: null,
    senderPubKey: null,
    isSecureMode: false,
    timestamp: now - 1000 * 60 * minutesAgo,
  });

  return [
    mail(
      "bob@cryptoshield.dev",
      "alice@cryptoshield.dev",
      "Workshop schedule for Friday",
      "<p>Hey Alice,</p><p>The blockchain workshop starts at <b>10:00 AM</b> in Lab 2. Bring your laptop.</p><p>— Bob</p>",
      42,
    ),
    mail(
      "ceo@cryptoshield.dev",
      "alice@cryptoshield.dev",
      "Quarterly security review",
      "<p>Hi team,</p><p>Please review the attached transport findings before Thursday.</p><p>Thanks,<br/>CEO</p>",
      300,
    ),
    mail(
      "alice@cryptoshield.dev",
      "bob@cryptoshield.dev",
      "Re: Workshop schedule for Friday",
      "<p>Works for me — see you at 10.</p>",
      30,
    ),
    mail(
      "admin@bank.com",
      "bob@cryptoshield.dev",
      "Wire transfer authorized — ACCT-8842",
      '<p>Transfer confirmed. Reference <b>QX-9931</b>.</p><p>— Bank operations</p>',
      95,
    ),
    mail(
      "security@cryptoshield.dev",
      "admin@bank.com",
      "Certificate rotation notice",
      "<p>Your signing certificate is due for rotation at the end of the quarter.</p>",
      600,
    ),
  ];
}
