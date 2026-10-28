"use client";

/**
 * Receive-side pipeline for a selected message (secure mode):
 *
 *   directory lookup (claimed sender's registered key)
 *     → RSA-OAEP unwrap (recipient private key)
 *     → AES-GCM decrypt
 *     → SHA-256 re-hash
 *     → RSA-PSS verification + directory key binding
 *     → certificate revocation check (CRL simulation)
 *     → DOMPurify sanitization of the recovered HTML
 *
 * Every step streams into the inspector's crypto timeline and every detected
 * attack is reported to the audit log. Never throws: failures become a
 * `VerificationResult` (SPOOFED / TAMPERED / REVOKED) so the UI can render a
 * banner instead of crashing.
 *
 * `refreshToken` lets the mailbox re-run the pipeline after a CRL change (the
 * revocation list lives on the server, so the directory lookup must repeat).
 *
 * Sender's own messages (`localPlaintext`) skip decryption — the sender
 * possesses the plaintext — but still run signature + binding + CRL checks.
 */

import { useEffect, useRef, useState } from "react";
import type {
  EmailPayload,
  SecurityIncidentInput,
  SecurePayload,
  VerificationResult,
} from "@/lib/types";
import { decryptAndVerify, verifyPayloadSignature } from "@/lib/crypto";
import { sanitizeHtml } from "@/lib/sanitize";
import { fetchDirectoryKey } from "@/lib/api/emailClient";
import { classifySanitization, classifyVerification } from "@/lib/audit/classify";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useTransport } from "@/store/TransportContext";
import { useAuth } from "@/store/AuthContext";
import { useAudit } from "@/store/AuditContext";

export interface SecureMessageView {
  /** "working" while the pipeline runs. */
  phase: "idle" | "working" | "done";
  /** Verification report (null until done). */
  verification: VerificationResult | null;
  /** Decrypted (and sanitized) content, or null when unavailable. */
  payload: SecurePayload | null;
  /** What DOMPurify removed before the body reached the renderer. */
  sanitization?: { stripped: boolean; removedChars: number };
}

const IDLE: SecureMessageView = { phase: "idle", verification: null, payload: null };

export function useSecureMessage(
  email: EmailPayload | null,
  /** Bump to force a re-run (e.g. after a certificate is revoked). */
  refreshToken = 0,
): SecureMessageView {
  const { account: profile } = useAuth();
  const { mode } = useSecurityMode();
  const { recordPacket, recordCryptoStep } = useTransport();
  const { recordIncident } = useAudit();
  const [state, setState] = useState<SecureMessageView>(IDLE);

  // Guards against duplicate incidents when the effect re-runs for the same
  // message (profile/mode/refresh changes must not double-report).
  const reportedRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;

    if (!email) {
      setState(IDLE);
      return;
    }

    // `const` alias keeps TypeScript's null-narrowing inside the closure.
    const message = email;
    const reportOnce = (key: string, incident: SecurityIncidentInput | null) => {
      if (!incident) return;
      const full = `${message.id}:${key}`;
      if (reportedRef.current.has(full)) return;
      reportedRef.current.add(full);
      recordIncident(incident);
    };

    // Phase-1 plaintext messages: nothing to decrypt — flag as unverified.
    if (!email.isSecureMode) {
      setState({
        phase: "done",
        verification: {
          status: "plaintext",
          reason:
            "Message was sent in UNSAFE mode: raw plaintext on the wire, no digital signature.",
        },
        payload: null,
      });
      return;
    }

    setState({ phase: "working", verification: null, payload: null });

    (async () => {
      // ① Directory lookup for the CLAIMED sender (trust root — never use
      //    the message's own key without comparing it to this entry).
      let directory = null;
      try {
        directory = await fetchDirectoryKey(email.sender, mode, recordPacket);
      } catch {
        directory = null; // unknown sender → binding check will fail red
      }

      if (cancelled) return;

      try {
        let verification: VerificationResult;
        let payload: SecurePayload | null = null;
        let failedStage: "unwrap" | "decrypt" | "payload" | undefined;

        if (email.localPlaintext && email.signature && email.senderPubKey) {
          // ── Sender-side view: verify over the local plaintext copy ──
          payload = {
            sender: email.sender,
            recipient: email.recipient,
            subject: email.subject,
            body: email.body,
            timestamp: email.timestamp,
          };
          verification = await verifyPayloadSignature(
            payload,
            email.signature,
            email.senderPubKey,
            directory,
            recordCryptoStep,
          );
        } else {
          // ── Full receive pipeline: decrypt → verify → bind → CRL ────
          if (!profile) {
            if (!cancelled) {
              setState({ phase: "working", verification: null, payload: null });
            }
            return; // re-runs when the profile lands (dependency below)
          }

          const outcome = await decryptAndVerify(
            email,
            profile.keyPair.encryption.privateKey,
            directory,
            recordCryptoStep,
          );
          verification = outcome.verification;
          payload = outcome.payload;
          failedStage = outcome.failedStage;

          // Your OWN Sent copy of a message encrypted to someone else can
          // never be decrypted by you (recipient-only encryption) — unwrap
          // fails because the AES key was wrapped to THEIR key. That is
          // correct behavior, NOT tampering, so do not show a red verdict.
          if (
            !payload &&
            outcome.failedStage === "unwrap" &&
            profile !== null &&
            email.sender.toLowerCase() === profile.email.toLowerCase()
          ) {
            verification = {
              status: "plaintext",
              reason:
                "Sent by you to another recipient — only their private key can decrypt this server copy, and your local plaintext copy is not in this session.",
            };
            failedStage = undefined;
          }
        }

        // ② Audit: every detected attack is recorded exactly once.
        reportOnce("verdict", classifyVerification(verification, message, failedStage));

        // ③ Sanitize recovered HTML BEFORE it can reach the renderer, and
        //    record any stripped markup as a sanitization incident.
        let sanitization: SecureMessageView["sanitization"];
        if (payload) {
          const original = payload.body;
          const started = performance.now();
          const clean = await sanitizeHtml(original);
          const removedChars = Math.max(0, original.length - clean.length);
          sanitization = { stripped: removedChars > 0, removedChars };
          recordCryptoStep({
            phase: "sanitize",
            label: "DOMPurify HTML sanitization",
            detail:
              clean === original
                ? "markup passed sanitization unchanged (no scripts/handlers found)"
                : `${original.length - clean.length} unsafe characters/attributes stripped before rendering`,
            durationMs: performance.now() - started,
            status: "ok",
          });
          reportOnce("sanitize", classifySanitization(original, clean, message));
          payload = { ...payload, body: clean };
        }

        if (!cancelled) {
          setState({ phase: "done", verification, payload, sanitization });
        }
      } catch (cause) {
        if (!cancelled) {
          setState({
            phase: "done",
            verification: {
              status: "spoofed-tampered",
              reason: `Verification pipeline error: ${
                cause instanceof Error ? cause.message : String(cause)
              }`,
            },
            payload: null,
          });
        }
      }
    })();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [email?.id, email?.timestamp, profile, mode, refreshToken]);

  return state;
}
