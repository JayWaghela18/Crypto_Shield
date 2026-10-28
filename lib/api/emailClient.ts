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
import { STATIC_RELAY, relayFetch } from "@/lib/api/staticRelay";

const API_BASE = "/api/email";
const KEYS_BASE = "/api/keys";

/**
 * All network traffic goes through this one function.
 *
 * On a server deployment it is plain `fetch`. On the static (GitHub Pages)
 * build there is no server, so it resolves against the localStorage relay in
 * `lib/api/staticRelay.ts` — same routes, same status codes, local storage.
 */
export async function apiFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  if (STATIC_RELAY) return relayFetch(input, init);
  return fetch(input, init);
}

/** Recorder callback — wired to TransportContext.recordPacket. */
export type PacketRecorder = (packet: TransportPacket) => void;

/** Marker header so the inspector never pretends local bytes hit a server. */
const RELAY_HEADER: Record<string, string> = STATIC_RELAY
  ? { "x-relay": "localStorage" }
  : {};

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
        ...RELAY_HEADER,
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
        ...RELAY_HEADER,
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

  const response = await apiFetch(API_BASE, {
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

  const response = await apiFetch(url, { headers: { Accept: "application/json" } });
  const text = await response.text();
  recordInbound("GET", url, response, text, mode, record);

  if (!response.ok) {
    throw new Error(`No public key registered for ${address}`);
  }
  return JSON.parse(text) as DirectoryEntry;
}

/**
 * KEY REGISTRATION — publish this browser's public keys (+ account metadata)
 * to the directory. Public material only; private keys never leave the page.
 */
export async function registerPublicKey(
  address: string,
  encryptionPub: JsonWebKey,
  signingPub: JsonWebKey,
  mode: SecurityMode,
  record?: PacketRecorder,
  meta?: { name?: string; role?: string },
): Promise<{ fingerprint: string; entry: DirectoryEntry }> {
  // POST /api/keys (same route file as GET lookup — method dispatch).
  const url = KEYS_BASE;
  const body = JSON.stringify({
    address,
    encryptionPub,
    signingPub,
    name: meta?.name,
    role: meta?.role,
  });
  buildOutboundPacket("POST", url, body, mode, record);

  const response = await apiFetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  const text = await response.text();
  recordInbound("POST", url, response, text, mode, record);

  if (!response.ok) {
    throw new Error(`Key registration failed: ${response.status} ${text}`);
  }
  return JSON.parse(text) as { fingerprint: string; entry: DirectoryEntry };
}

/** DIRECTORY LISTING — every address mail can be addressed to. */
export async function fetchDirectoryList(
  mode: SecurityMode,
  record?: PacketRecorder,
): Promise<DirectoryEntry[]> {
  const url = `${KEYS_BASE}?list=1`;
  buildOutboundPacket("GET", url, "", mode, record);

  const response = await apiFetch(url, { headers: { Accept: "application/json" } });
  const text = await response.text();
  recordInbound("GET", url, response, text, mode, record);

  if (!response.ok) {
    throw new Error(`Directory listing failed: ${response.status} ${text}`);
  }
  const parsed = JSON.parse(text) as { entries?: DirectoryEntry[] };
  return parsed.entries ?? [];
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

  const response = await apiFetch(url, { headers: { Accept: "application/json" } });

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

  const response = await apiFetch(url, {
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

/**
 * Best-effort directory lookup for a typed address — returns null instead of
 * throwing when the address is unknown (or the relay is unavailable).
 * Used by the sign-in form to tell "already registered" from "new address".
 */
export async function tryFetchDirectoryEntry(
  address: string,
): Promise<DirectoryEntry | null> {
  try {
    const url = `${KEYS_BASE}?address=${encodeURIComponent(address)}`;
    const response = await apiFetch(url, {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) return null;
    return (await response.json()) as DirectoryEntry;
  } catch {
    return null;
  }
}

/** Fetch the simulated Certificate Revocation List. */
export async function fetchCrl(
  mode: SecurityMode,
  record?: PacketRecorder,
): Promise<RevokedCertificate[]> {
  const url = `${KEYS_BASE}?crl=1`;
  buildOutboundPacket("GET", url, "", mode, record);

  const response = await apiFetch(url, { headers: { Accept: "application/json" } });
  const text = await response.text();
  recordInbound("GET", url, response, text, mode, record);

  if (!response.ok) {
    throw new Error(`CRL fetch failed: ${response.status} ${text}`);
  }
  const parsed = JSON.parse(text) as { crl?: RevokedCertificate[] };
  return parsed.crl ?? [];
}
