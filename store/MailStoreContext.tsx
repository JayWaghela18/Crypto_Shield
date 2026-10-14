"use client";

/**
 * Mailbox state store — loads inbox/sent and sends new messages, routing
 * every request through the packet-recording client so the inspector stays
 * live.
 *
 * Phase 2: when the global mode is SECURE, `sendDraft` packages the message
 * with the hybrid engine BEFORE it touches the network:
 *
 *   directory lookup (recipient's public key)
 *     → AES-256-GCM payload encryption
 *     → RSA-OAEP wrapping of the AES key
 *     → SHA-256 hash + RSA-PSS signature
 *     → POST of the opaque envelope (no plaintext on the wire)
 *
 * Each crypto step streams into the inspector via recordCryptoStep.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { EmailDraft, EmailPayload, MailboxFolder } from "@/lib/types";
import {
  fetchDirectoryKey,
  fetchMailboxRequest,
  sendEmailRequest,
} from "@/lib/api/emailClient";
import { hybridEncrypt } from "@/lib/crypto";
import {
  tamperCiphertext,
  tamperPlaintext,
  type SendAttackOptions,
} from "@/lib/attacks";
import { classifyMitmInterception } from "@/lib/audit/classify";
import { useSecurityMode } from "@/store/SecurityModeContext";
import { useTransport } from "@/store/TransportContext";
import { useAudit } from "@/store/AuditContext";
import { useUserProfile } from "@/store/UserProfileContext";
import { CURRENT_USER } from "@/lib/constants";

interface MailStoreContextValue {
  /** Messages currently shown (for `activeFolder`). */
  emails: EmailPayload[];
  activeFolder: MailboxFolder;
  isLoading: boolean;
  /** Error from the last send/load, surfaced in the UI. */
  error: string | null;
  /** Success message after a send. */
  notice: string | null;
  /** Load a folder (inbox/sent) from the API. */
  loadFolder: (folder: MailboxFolder) => Promise<void>;
  /**
   * Send a draft through the current security mode's transport.
   * `options.tamper` runs the Phase 3 MITM simulation: the payload is
   * altered while "in transit" (one character) before it reaches the server.
   */
  sendDraft: (
    draft: EmailDraft,
    options?: SendAttackOptions,
  ) => Promise<EmailPayload | null>;
  clearNotice: () => void;
}

const MailStoreContext = createContext<MailStoreContextValue | null>(null);

/**
 * Sender-side Sent copies persist in localStorage (like a real mail client's
 * Sent folder) so you can still read mail you sent to OTHERS after a reload —
 * recipient-only encryption means the server copy is opaque even to you.
 * ⚠ Demo tradeoff: production clients should encrypt this at rest too.
 */
const SENT_STORAGE_KEY = "cryptoshield.sent.v1";

function loadStoredSent(): EmailPayload[] {
  try {
    if (typeof window === "undefined") return [];
    const raw = window.localStorage.getItem(SENT_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as EmailPayload[];
    return Array.isArray(parsed) ? parsed.slice(0, 50) : [];
  } catch {
    return [];
  }
}

function persistSent(entries: EmailPayload[]): void {
  try {
    window.localStorage.setItem(SENT_STORAGE_KEY, JSON.stringify(entries.slice(0, 50)));
  } catch {
    // quota/privacy errors are non-fatal — the in-memory copy still works
  }
}

export function MailStoreProvider({ children }: { children: ReactNode }) {
  const { mode } = useSecurityMode();
  const { recordPacket, recordCryptoStep } = useTransport();
  const { recordIncident } = useAudit();
  const { profile, registered } = useUserProfile();

  const [emails, setEmails] = useState<EmailPayload[]>([]);
  // Messages this browser session sent. Kept locally so (a) spoofed sends
  // (From != current user) still show under Sent, and (b) the sender keeps a
  // plaintext copy — a recipient-only encryption scheme means the server copy
  // is opaque even to the sender.
  const [sessionSent, setSessionSent] = useState<EmailPayload[]>([]);
  const [activeFolder, setActiveFolder] = useState<MailboxFolder>("inbox");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const activeFolderRef = useRef<MailboxFolder>("inbox");
  activeFolderRef.current = activeFolder;

  // Restore sender-side plaintext copies after mount (avoids hydration mismatch).
  useEffect(() => {
    const stored = loadStoredSent();
    if (stored.length > 0) setSessionSent(stored);
  }, []);

  const updateSessionSent = useCallback((updater: (prev: EmailPayload[]) => EmailPayload[]) => {
    setSessionSent((prev) => {
      const next = updater(prev);
      persistSent(next);
      return next;
    });
  }, []);

  const loadFolder = useCallback(
    async (folder: MailboxFolder) => {
      setActiveFolder(folder);
      setIsLoading(true);
      setError(null);
      try {
        // Every fetch is recorded → shows up live in the transport inspector.
        const list = await fetchMailboxRequest(folder, CURRENT_USER, mode, recordPacket);
        if (folder === "sent") {
          // Local session copies WIN over the server copy of the same id:
          // they carry the sender's plaintext view + localPlaintext marker.
          const localIds = new Set(sessionSent.map((e) => e.id));
          const merged = [
            ...sessionSent,
            ...list.filter((e) => !localIds.has(e.id)),
          ].sort((a, b) => b.timestamp - a.timestamp);
          setEmails(merged);
        } else {
          setEmails(list);
        }
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : "Failed to load mail");
      } finally {
        setIsLoading(false);
      }
    },
    [mode, recordPacket, sessionSent],
  );

  // Refresh the visible folder once this identity is published to the
  // directory — that is when Bob's server-signed secure seed becomes
  // decryptable/visible (it is created during registration).
  const loadedAfterRegister = useRef(false);
  useEffect(() => {
    if (registered && !loadedAfterRegister.current) {
      loadedAfterRegister.current = true;
      void loadFolder(activeFolderRef.current);
    }
  }, [registered, loadFolder]);

  const sendDraft = useCallback(
    async (draft: EmailDraft, options?: SendAttackOptions) => {
      setIsLoading(true);
      setError(null);
      setNotice(null);
      try {
        let message: EmailPayload;

        if (mode === "secure") {
          if (!profile) throw new Error("Keys are still generating — retry shortly");

          // ① Directory lookup: recipient's published RSA-OAEP public key.
          const recipientKeys = await fetchDirectoryKey(
            draft.recipient,
            mode,
            recordPacket,
          );

          // ②–⑥ Hybrid packaging (each step is logged to the inspector).
          const timestamp = Date.now();
          const envelope = await hybridEncrypt(
            {
              sender: draft.sender,
              recipient: draft.recipient,
              subject: draft.subject,
              body: draft.body,
              timestamp,
            },
            recipientKeys.encryptionPub,
            {
              address: draft.sender,
              publicKey: {
                encryption: profile.keyPair.encryption.publicKey,
                signing: profile.keyPair.signing.publicKey,
              },
              signingPriv: profile.keyPair.signing.privateKey,
            },
            recordCryptoStep,
          );

          // Phase 3 MITM simulation: flip one character of the ciphertext
          // while it is "in transit" — the attacker cannot read the payload,
          // only corrupt it. The receiver's GCM tag check will catch it.
          let wireEnvelope = envelope;
          if (options?.tamper) {
            wireEnvelope = {
              ...envelope,
              payloadCiphertext: tamperCiphertext(envelope.payloadCiphertext),
            };
            recordCryptoStep({
              phase: "mitm",
              label: "MITM interception (simulated)",
              detail:
                "altered 1 base64 character of payloadCiphertext before forwarding — attacker cannot read the plaintext, only corrupt it",
              durationMs: 0,
              status: "ok",
            });
            recordIncident(
              classifyMitmInterception(
                "secure",
                draft,
                "An attacker altered one base64 character of the AES-GCM ciphertext in transit. The plaintext stays unreadable; the receiver's GCM authentication tag detects the change.",
              ),
            );
          }

          // ⑦ POST the opaque envelope — NO plaintext subject/body on wire.
          const stored = await sendEmailRequest(
            {
              sender: draft.sender,
              recipient: draft.recipient,
              subject: "(end-to-end encrypted)",
              body: "",
              isSecureMode: true,
              ciphertext: wireEnvelope.payloadCiphertext,
              symmetricKey: wireEnvelope.encryptedSymmetricKey,
              signature: wireEnvelope.signature,
              senderPubKey: wireEnvelope.senderPubKey,
            },
            mode,
            recordPacket,
          );

          // Local plaintext copy for the sender's Sent view + verification.
          message = {
            ...stored,
            timestamp, // the timestamp covered by the signature
            subject: draft.subject,
            body: draft.body,
            localPlaintext: true,
          };
          updateSessionSent((prev) => [message, ...prev]);
          setNotice(
            `End-to-end encrypted + signed → ${draft.recipient} (AES-256-GCM / RSA-OAEP / RSA-PSS)`,
          );
          return message;
        }

        // Unsafe engine: raw plaintext, spoofable sender (Phase 1 behavior).
        // Phase 3 MITM simulation: alter one character of the plaintext body
        // in transit — with no integrity check the recipient cannot tell.
        let wireDraft = draft;
        if (options?.tamper) {
          wireDraft = { ...draft, body: tamperPlaintext(draft.body) };
          recordCryptoStep({
            phase: "mitm",
            label: "MITM interception (simulated)",
            detail:
              "altered 1 character of the plaintext body before forwarding — no integrity check exists in unsafe mode",
            durationMs: 0,
            status: "ok",
          });
          recordIncident(
            classifyMitmInterception(
              "unsafe",
              draft,
              "An attacker altered one character of the plaintext body in transit. With no integrity check, the recipient reads the tampered message as genuine.",
            ),
          );
        }

        message = await sendEmailRequest(
          { ...wireDraft, isSecureMode: false },
          mode,
          recordPacket,
        );
        updateSessionSent((prev) => [message, ...prev]);
        setNotice(`Message accepted for ${draft.recipient}`);
        return message;
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : "Failed to send");
        return null;
      } finally {
        setIsLoading(false);
      }
    },
    [mode, profile, recordPacket, recordCryptoStep, recordIncident, updateSessionSent],
  );

  const clearNotice = useCallback(() => setNotice(null), []);

  const value = useMemo<MailStoreContextValue>(
    () => ({
      emails,
      activeFolder,
      isLoading,
      error,
      notice,
      loadFolder,
      sendDraft,
      clearNotice,
    }),
    [emails, activeFolder, isLoading, error, notice, loadFolder, sendDraft, clearNotice],
  );

  return <MailStoreContext.Provider value={value}>{children}</MailStoreContext.Provider>;
}

/** Access mailbox state/actions. Throws if used outside the provider. */
export function useMailStore(): MailStoreContextValue {
  const ctx = useContext(MailStoreContext);
  if (!ctx) throw new Error("useMailStore must be used within MailStoreProvider");
  return ctx;
}
