/**
 * CryptoShield — Phase 3 attack simulation library.
 *
 * Three explicit, user-triggered attacks. Each one runs against the CURRENT
 * security mode so the same button demonstrates failure in Unsafe Mode and
 * defense in Secure Mode:
 *
 *  1. SPOOF      — send as admin@bank.com WITHOUT holding their private key.
 *  2. MITM       — intercept the outbound payload in transit and alter
 *                  exactly one character before forwarding.
 *  3. STORED XSS — inject an <img onerror> script into the message body.
 *
 * ⚠ All of it is deliberately hostile code, isolated to this local lab.
 */

import type { EmailDraft } from "@/lib/types";
import { CURRENT_USER, SPOOF_TARGET } from "@/lib/constants";

/** The three simulations the Attack Lab can run. */
export type AttackId = "spoof" | "mitm" | "xss";

/** Options threaded through MailStore.sendDraft by the Attack Lab. */
export interface SendAttackOptions {
  /** MITM simulation: alter the payload while it is "in transit". */
  tamper?: boolean;
}

/* ------------------------------------------------------------------ */
/* Attack 1 — spoofed sender                                           */
/* ------------------------------------------------------------------ */

export function spoofedEmailDraft(): EmailDraft {
  return {
    sender: SPOOF_TARGET, // claimed From — this client does NOT hold this key
    recipient: CURRENT_USER,
    subject: "URGENT: verify your bank account or it will be locked",
    body: "<p>Dear customer,</p><p>Confirm your credentials within 24 hours or your account will be suspended.</p><p>— <b>Support Team</b></p>",
  };
}

/* ------------------------------------------------------------------ */
/* Attack 2 — MITM tampering                                           */
/* ------------------------------------------------------------------ */

export function mitmEmailDraft(): EmailDraft {
  return {
    sender: CURRENT_USER,
    recipient: CURRENT_USER,
    subject: "Confidential transfer authorization",
    body: "<p>Please transfer $100 to account ACCT-12345. Reference: QX-9931.</p>",
  };
}

/**
 * Alter EXACTLY ONE character of a plaintext body (unsafe mode). The first
 * digit is swapped: "$100" → "$900" — a classic wire-level money change.
 * The recipient has no integrity check, so the result reads normally.
 */
export function tamperPlaintext(body: string): string {
  return body.replace(/\d/, (d) => (d === "9" ? "8" : "9"));
}

/**
 * Alter EXACTLY ONE base64 character of the envelope's ciphertext (secure
 * mode). The attacker cannot read the payload, so they can only corrupt the
 * bytes in flight — which trips the AES-GCM authentication tag on receive
 * ("Tampering Detected").
 */
export function tamperCiphertext(ciphertext: string): string {
  if (ciphertext.length < 4) return ciphertext;
  const idx = Math.floor(ciphertext.length / 2);
  const original = ciphertext[idx];
  const replacement = original === "A" ? "B" : "A";
  return ciphertext.slice(0, idx) + replacement + ciphertext.slice(idx + 1);
}

/* ------------------------------------------------------------------ */
/* Attack 3 — stored XSS payload                                       */
/* ------------------------------------------------------------------ */

/**
 * Classic Stored XSS body. In Unsafe Mode the onerror fires when the email
 * is opened — the script runs with the reader's session (simulated hijack
 * alert). In Secure Mode DOMPurify strips the handler before render.
 */
export function xssEmailDraft(): EmailDraft {
  return {
    // Sent from this identity so Secure Mode signature verification passes
    // (green) and the ONLY thing between the script and execution is
    // DOMPurify — exactly the contrast Phase 3 wants to demonstrate.
    sender: CURRENT_USER,
    recipient: CURRENT_USER,
    subject: "🎁 You have won a free security audit!",
    body: '<p>Click to claim your prize.</p><img src="x" onerror="alert(\'⚠ STORED XSS — session hijacked (simulated): your cryptoshield session cookie was stolen\'); document.title=\'XSS_SESSION_HIJACKED\'">',
  };
}
