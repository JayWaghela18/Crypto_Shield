/**
 * Email transport client — the ONLY place the UI talks to /api/email.
 *
 * Every request and response is serialized into a `TransportPacket` and
 * handed to the inspector's recorder, so the right-hand panel shows exactly
 * what travels across the wire, byte for byte, in real time.
 *
 * In unsafe mode the body is raw plaintext JSON. Phase 2's secure mode will
 * encrypt here (client-side Web Crypto) before the POST, meaning the packet
 * inspector will show only opaque ciphertext.
 */

import type {
  DirectoryEntry,
  EmailDraft,
  EmailPayload,
  RevokedCertificate,
  SecurityMode,
  SenderPublicKeys,
  TransportPacket,
} from "@/lib/types";

const API_BASE = "/api/email";
const KEYS_BASE = "/api/keys";

/** Recorder callback — wired to TransportContext.recordPacket. */
export type PacketRecorder = (packet: TransportPacket) => void;

/** UTF-8 byte length of a string (what actually goes on the wire). */
function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

function makePacket(
  partial: Omit<TransportPacket, "id" | "sizeBytes" | "timestamp">,
): TransportPacket {
  return {
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    sizeBytes: byteLength(partial.body),
    ...partial,
  };
}

/** Serialize a request onto the "wire" and record the outbound packet. */
function buildOutboundPacket(
  method: string,
  url: string,
  body: string,
  mode: SecurityMode,
  record?: PacketRecorder,
): void {
  record?.(
    makePacket({
      direction: "outbound",
      method,
      url,
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body,
      mode,
    }),
  );
}

/** Record the response as an inbound packet (status + body as received). */
function recordInbound(
  method: string,
  url: string,
  response: Response,
  body: string,
  mode: SecurityMode,
  record?: PacketRecorder,
): void {
  record?.(
    makePacket({
      direction: "inbound",
      method,
      url,
      status: response.status,
      headers: {
        "content-type": response.headers.get("content-type") ?? "(none)",
        "cache-control": response.headers.get("cache-control") ?? "(none)",
      },
      body,
      mode,
    }),
  );
}

/**
 * What the send button posts. Unsafe mode sends plaintext fields; secure
 * mode sends the opaque hybrid envelope instead (body/subject stay empty on
 * the wire — real content lives inside `ciphertext`).
 */
export type OutgoingMessage = EmailDraft & {
  isSecureMode: boolean;
  ciphertext?: string | null;
  symmetricKey?: string | null;
  signature?: string | null;
  senderPubKey?: SenderPublicKeys | null;
};

/** SEND — POST a message (plaintext or secure envelope) to the engine. */
export async function sendEmailRequest(
  message: OutgoingMessage,
  mode: SecurityMode,
  record?: PacketRecorder,
): Promise<EmailPayload> {
  const body = JSON.stringify(message);
  buildOutboundPacket("POST", API_BASE, body, mode, record);

  const response = await fetch(API_BASE, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });

  const text = await response.text();
  recordInbound("POST", API_BASE, response, text, mode, record);

  if (!response.ok) {
    throw new Error(`Send failed: ${response.status} ${text}`);
  }
  return JSON.parse(text) as EmailPayload;
}

/** DIRECTORY LOOKUP — fetch an address's registered public keys. */
export async function fetchDirectoryKey(
  address: string,
  mode: SecurityMode,
  record?: PacketRecorder,
): Promise<DirectoryEntry> {
  const url = `${KEYS_BASE}?address=${encodeURIComponent(address)}`;
  buildOutboundPacket("GET", url, "", mode, record);

  const response = await fetch(url, { headers: { Accept: "application/json" } });
  const text = await response.text();
  recordInbound("GET", url, response, text, mode, record);

  if (!response.ok) {
    throw new Error(`No public key registered for ${address}`);
  }
  return JSON.parse(text) as DirectoryEntry;
}

/** KEY REGISTRATION — publish this browser's public keys to the directory. */
export async function registerPublicKey(
  address: string,
  encryptionPub: JsonWebKey,
  signingPub: JsonWebKey,
  mode: SecurityMode,
  record?: PacketRecorder,
): Promise<{ fingerprint: string; seeded: boolean }> {
  // POST /api/keys (same route file as GET lookup — method dispatch).
  const url = KEYS_BASE;
  const body = JSON.stringify({ address, encryptionPub, signingPub });
  buildOutboundPacket("POST", url, body, mode, record);

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  const text = await response.text();
  recordInbound("POST", url, response, text, mode, record);

  if (!response.ok) {
    throw new Error(`Key registration failed: ${response.status} ${text}`);
  }
  return JSON.parse(text) as { fingerprint: string; seeded: boolean };
}

/** RECEIVE — GET a mailbox folder (inbox or sent). */
export async function fetchMailboxRequest(
  folder: "inbox" | "sent",
  user: string,
  mode: SecurityMode,
  record?: PacketRecorder,
): Promise<EmailPayload[]> {
  const url = `${API_BASE}?mailbox=${folder}&user=${encodeURIComponent(user)}`;
  buildOutboundPacket("GET", url, "", mode, record);

  const response = await fetch(url, { headers: { Accept: "application/json" } });

  const text = await response.text();
  recordInbound("GET", url, response, text, mode, record);

  if (!response.ok) {
    throw new Error(`Load failed: ${response.status} ${text}`);
  }
  return JSON.parse(text) as EmailPayload[];
}

/**
 * CRL SIMULATION — revoke or reinstate a sender's certificate.
 * Revocation never alters the key material: the signature keeps verifying,
 * and only the revocation check rejects the message.
 */
export async function setCertificateRevocation(
  address: string,
  revoked: boolean,
  mode: SecurityMode,
  record?: PacketRecorder,
  reason?: string,
): Promise<DirectoryEntry> {
  const url = KEYS_BASE;
  const body = JSON.stringify({
    action: revoked ? "revoke" : "unrevoke",
    address,
    reason,
  });
  buildOutboundPacket("POST", url, body, mode, record);

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  const text = await response.text();
  recordInbound("POST", url, response, text, mode, record);

  if (!response.ok) {
    throw new Error(`Revocation update failed: ${response.status} ${text}`);
  }
  return JSON.parse(text) as DirectoryEntry;
}

/** Fetch the simulated Certificate Revocation List. */
export async function fetchCrl(
  mode: SecurityMode,
  record?: PacketRecorder,
): Promise<RevokedCertificate[]> {
  const url = `${KEYS_BASE}?crl=1`;
  buildOutboundPacket("GET", url, "", mode, record);

  const response = await fetch(url, { headers: { Accept: "application/json" } });
  const text = await response.text();
  recordInbound("GET", url, response, text, mode, record);

  if (!response.ok) {
    throw new Error(`CRL fetch failed: ${response.status} ${text}`);
  }
  const parsed = JSON.parse(text) as { crl?: RevokedCertificate[] };
  return parsed.crl ?? [];
}
