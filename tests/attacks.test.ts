/**
 * @vitest-environment jsdom
 *
 * CryptoShield — attack simulation tests.
 *
 * Covers the two defences the Attack Lab exercises:
 *   1. A spoofed `From` header cannot pass RSA signature verification in
 *      Secure Mode (directory key-binding + RSA-PSS).
 *   2. Malicious HTML in an email body is neutralized by DOMPurify *before* it
 *      reaches the DOM.
 *
 * jsdom is required for the sanitization assertions (DOMPurify + `document`);
 * `tests/setup.ts` backs jsdom's missing `crypto.subtle` with Node's Web Crypto
 * so the signature tests run in the same file.
 */

import { describe, expect, it } from "vitest";

import {
  mitmEmailDraft,
  spoofedEmailDraft,
  tamperCiphertext,
  tamperPlaintext,
  xssEmailDraft,
} from "@/lib/attacks";
import {
  decryptAndVerify,
  hybridEncrypt,
  jwkFingerprint,
  type SenderIdentity,
} from "@/lib/crypto";
import { generateUserKeyPairs } from "@/lib/crypto/webcrypto";
import { sanitizeHtml } from "@/lib/sanitize";
import { CURRENT_USER, SPOOF_TARGET } from "@/lib/constants";
import type {
  DirectoryEntry,
  EmailPayload,
  SecurePayload,
  UserKeyPair,
} from "@/lib/types";

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

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

async function makeDirectory(
  address: string,
  keys: UserKeyPair,
): Promise<DirectoryEntry> {
  return {
    address,
    encryptionPub: keys.encryption.publicKey,
    signingPub: keys.signing.publicKey,
    fingerprint: await jwkFingerprint(keys.signing.publicKey),
    source: "demo",
  };
}

function spoofedPayload(): SecurePayload {
  const draft = spoofedEmailDraft();
  return {
    sender: draft.sender,
    recipient: draft.recipient,
    subject: draft.subject,
    body: draft.body,
    timestamp: 1_700_000_000_000,
  };
}

function toEmail(
  envelope: Awaited<ReturnType<typeof hybridEncrypt>>,
  payload: SecurePayload,
): EmailPayload {
  return {
    id: "attack-message-id",
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
/* 1. Spoofed sender header                                            */
/* ------------------------------------------------------------------ */

describe("spoofed sender verification", () => {
  it("the spoof draft claims the bank's address from this (attacker) client", () => {
    const draft = spoofedEmailDraft();
    expect(draft.sender).toBe(SPOOF_TARGET);
    expect(draft.recipient).toBe(CURRENT_USER);
  });

  it("fails key-binding when the signer is not the bank's published key", async () => {
    // Attacker (this browser) holds its OWN key, not the bank's.
    const attacker = await generateUserKeyPairs();
    // The bank publishes a genuinely different key to the directory.
    const bank = await generateUserKeyPairs();

    const payload = spoofedPayload();
    const envelope = await hybridEncrypt(
      payload,
      attacker.encryption.publicKey, // recipient = the attacker's own inbox
      senderIdentity(SPOOF_TARGET, attacker), // claims to be the bank
    );

    const outcome = await decryptAndVerify(
      toEmail(envelope, payload),
      attacker.encryption.privateKey,
      await makeDirectory(SPOOF_TARGET, bank), // bank's real directory entry
    );

    // The body did decrypt (it *was* encrypted to this recipient), but the
    // sender cannot be authenticated — the UI shows a red warning banner.
    expect(outcome.payload).not.toBeNull();
    expect(outcome.verification.status).toBe("spoofed-unverified");
    expect(outcome.verification.reason).toMatch(/Key binding FAILED/i);
    expect(outcome.verification.fingerprint).not.toBe(
      outcome.verification.expectedFingerprint,
    );
  });

  it("fails RSA-PSS verification when the carried key is forged to the bank's", async () => {
    // A stronger attacker: swap in the bank's REAL public key so the directory
    // binding matches — but they still cannot sign with the bank's private key.
    const attacker = await generateUserKeyPairs();
    const bank = await generateUserKeyPairs();

    const payload = spoofedPayload();
    const envelope = await hybridEncrypt(
      payload,
      attacker.encryption.publicKey,
      senderIdentity(SPOOF_TARGET, attacker),
    );

    const forged = {
      ...envelope,
      senderPubKey: {
        encryption: bank.encryption.publicKey,
        signing: bank.signing.publicKey,
      },
    };

    const outcome = await decryptAndVerify(
      toEmail(forged, payload),
      attacker.encryption.privateKey,
      await makeDirectory(SPOOF_TARGET, bank), // binding now matches…
    );

    // …but the signature was made with the attacker's private key.
    expect(outcome.verification.status).toBe("spoofed-tampered");
    expect(outcome.verification.reason).toMatch(/signature INVALID/i);
  });

  it("accepts a genuine sender whose key matches the directory", async () => {
    const sender = await generateUserKeyPairs();
    const payload: SecurePayload = {
      sender: CURRENT_USER,
      recipient: "bob@cryptoshield.dev",
      subject: "hello",
      body: "<p>genuine</p>",
      timestamp: 1_700_000_000_000,
    };

    const envelope = await hybridEncrypt(
      payload,
      sender.encryption.publicKey,
      senderIdentity(CURRENT_USER, sender),
    );

    const outcome = await decryptAndVerify(
      toEmail(envelope, payload),
      sender.encryption.privateKey,
      await makeDirectory(CURRENT_USER, sender),
    );

    expect(outcome.verification.status).toBe("verified");
    expect(outcome.payload).toEqual(payload);
  });

  it("flags an unknown sender with no directory entry as unverified", async () => {
    const attacker = await generateUserKeyPairs();
    const payload = spoofedPayload();
    const envelope = await hybridEncrypt(
      payload,
      attacker.encryption.publicKey,
      senderIdentity(SPOOF_TARGET, attacker),
    );

    const outcome = await decryptAndVerify(
      toEmail(envelope, payload),
      attacker.encryption.privateKey,
      null, // no directory entry at all
    );

    expect(outcome.verification.status).toBe("spoofed-unverified");
    expect(outcome.verification.reason).toMatch(/No public key is registered/i);
  });
});

/* ------------------------------------------------------------------ */
/* 2. Stored XSS sanitization                                          */
/* ------------------------------------------------------------------ */

describe("DOMPurify sanitization before DOM insertion", () => {
  it("the XSS draft really carries an executable event handler", () => {
    expect(xssEmailDraft().body).toMatch(/onerror/i);
  });

  it("strips <script> tags while preserving safe markup", async () => {
    const dirty = "<p>hello</p><script>window.__xss = true;</script>";
    const clean = await sanitizeHtml(dirty);

    expect(clean).not.toMatch(/<script/i);
    expect(clean).toContain("<p>hello</p>");
  });

  it("removes the onerror handler from the attack payload", async () => {
    const clean = await sanitizeHtml(xssEmailDraft().body);

    expect(clean).not.toMatch(/onerror/i);
    expect(clean).not.toMatch(/alert/i);
  });

  it("inserts only safe DOM nodes after sanitization", async () => {
    const raw = xssEmailDraft().body;

    // Threat: before sanitization the handler lands in the DOM.
    const dirtyContainer = document.createElement("div");
    dirtyContainer.innerHTML = raw;
    expect(dirtyContainer.querySelector("img[onerror]")).not.toBeNull();

    // Defense: the sanitized body carries no script/executable attribute.
    const clean = await sanitizeHtml(raw);
    const safeContainer = document.createElement("div");
    safeContainer.innerHTML = clean;

    expect(safeContainer.querySelector("script")).toBeNull();
    expect(safeContainer.querySelector("img[onerror]")).toBeNull();
    expect(safeContainer.innerHTML).not.toMatch(/onerror/i);
  });

  it("neutralizes javascript: URLs in anchors", async () => {
    const clean = await sanitizeHtml('<a href="javascript:alert(1)">click</a>');
    expect(clean).not.toMatch(/javascript:/i);
  });
});

/* ------------------------------------------------------------------ */
/* 3. MITM tamper helpers (shared with the crypto suite)               */
/* ------------------------------------------------------------------ */

describe("MITM tamper helpers", () => {
  it("tamperPlaintext changes exactly one character ($100 → $900)", () => {
    const draft = mitmEmailDraft();
    const tampered = tamperPlaintext(draft.body);
    expect(tampered).not.toBe(draft.body);
    expect(tampered).toMatch(/\$900/);
    expect(tampered).toContain("ACCT-12345"); // the rest is untouched
  });

  it("tamperCiphertext changes exactly one base64 character", () => {
    const original = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=";
    const tampered = tamperCiphertext(original);
    expect(tampered).toHaveLength(original.length);
    const diffs = [...tampered].filter((c, i) => c !== original[i]);
    expect(diffs).toHaveLength(1);
  });
});
