/**
 * Classification of verification outcomes into security incidents.
 *
 * Keeps the "what counts as an attack" policy in one pure, testable place so
 * the UI layer only has to call `recordIncident`.
 */

import type {
  EmailPayload,
  SecurityIncidentInput,
  VerificationResult,
} from "@/lib/types";

/** Minimal message shape needed for reporting. */
type IncidentSubject = Pick<EmailPayload, "id" | "sender" | "recipient" | "subject">;

/**
 * Map a verification verdict to an incident. Returns null when the outcome is
 * benign (verified / plaintext / nothing detected).
 */
export function classifyVerification(
  verification: VerificationResult,
  email: IncidentSubject,
  failedStage?: "unwrap" | "decrypt" | "payload",
): SecurityIncidentInput | null {
  const base = {
    sender: email.sender,
    recipient: email.recipient,
    subject: email.subject,
    messageId: email.id,
    verdict: verification.status,
  };

  switch (verification.status) {
    case "spoofed-unverified":
      return {
        ...base,
        category: "spoofing",
        severity: "critical",
        title: "Spoofed sender blocked",
        detail: verification.reason,
        meta: {
          usedFingerprint: verification.fingerprint ?? "unknown",
          registeredFingerprint: verification.expectedFingerprint ?? "not registered",
        },
      };

    case "spoofed-tampered":
      // Unwrap succeeded but the GCM tag failed ⇒ the bytes were altered in
      // transit (MITM), not a sender forgery.
      if (failedStage === "decrypt") {
        return {
          ...base,
          category: "tampering",
          severity: "critical",
          title: "MITM tampering detected (ciphertext altered)",
          detail: verification.reason,
          meta: { failedStage: "decrypt" },
        };
      }
      return {
        ...base,
        category: "spoofing",
        severity: "critical",
        title: "Forged / invalid signature rejected",
        detail: verification.reason,
        meta: { failedStage: failedStage ?? "signature" },
      };

    case "revoked":
      return {
        ...base,
        category: "revoked-certificate",
        severity: "high",
        title: "Revoked certificate rejected",
        detail: verification.reason,
        meta: { revoked: true },
      };

    default:
      return null;
  }
}

/** Classify a DOMPurify sanitization result (null when nothing was stripped). */
export function classifySanitization(
  original: string,
  sanitized: string,
  email: IncidentSubject,
): SecurityIncidentInput | null {
  const stripped = original.length - sanitized.length;
  if (stripped <= 0) return null;

  return {
    category: "sanitization",
    severity: "medium",
    title: "Malicious markup stripped by DOMPurify",
    detail: `DOMPurify removed ${stripped} characters of unsafe markup (scripts, event handlers or javascript: URLs) before rendering.`,
    sender: email.sender,
    recipient: email.recipient,
    subject: email.subject,
    messageId: email.id,
    meta: {
      strippedChars: stripped,
      originalLength: original.length,
      sanitizedLength: sanitized.length,
    },
  };
}

/** An incident for the simulated MITM interception performed while sending. */
export function classifyMitmInterception(
  mode: "unsafe" | "secure",
  draft: { sender: string; recipient: string; subject: string },
  detail: string,
): SecurityIncidentInput {
  return {
    category: "mitm",
    severity: "high",
    title: "Man-in-the-middle interception simulated",
    detail,
    sender: draft.sender,
    recipient: draft.recipient,
    subject: draft.subject,
    meta: { simulatedMode: mode, detectability: mode === "secure" ? "detected on receive" : "undetectable" },
  };
}
