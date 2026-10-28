/**
 * Static relay — the GitHub Pages build of CryptoShield.
 *
 * A GitHub Pages site is a pile of static files: there is no Node process, so
 * `/api/email` and `/api/keys` (which need a server) do not exist there. This
 * module re-implements exactly those two routes against `localStorage`, so the
 * exported site keeps the whole lab working: send/receive, the public-key
 * directory, the CRL toggle and the transport inspector.
 *
 * Behaviour mirrors `app/api/email/route.ts` + `app/api/keys/route.ts` field
 * for field — including the *deliberate* lack of authentication in unsafe mode
 * — with two honest differences, surfaced to the user in the docs:
 *   1. Data lives in THIS browser only (no server, no other visitors, no sync).
 *   2. Packets recorded by the inspector carry an `x-relay: localStorage`
 *      header so the wire view never pretends bytes travelled to a server.
 *
 * Only bundled into the page when `NEXT_PUBLIC_STATIC_EXPORT=1` (see
 * `scripts/build-static.mjs`); the normal `npm run dev` / `npm run build`
 * never includes or runs this code.
 */

import type {
  DirectoryEntry,
  EmailDraft,
  EmailPayload,
  RevokedCertificate,
  SenderPublicKeys,
} from "@/lib/types";
import { jwkFingerprint } from "@/lib/crypto";
import { demoSeedEmails } from "@/lib/server/demoSeed";

/** True when this bundle was built as a static export (GitHub Pages). */
export const STATIC_RELAY = process.env.NEXT_PUBLIC_STATIC_EXPORT === "1";

const STORAGE_KEY = "cryptoshield.static-relay.v1";
const MAX_MESSAGES = 500;

interface RelayState {
  emails: EmailPayload[];
  keys: Record<string, DirectoryEntry>;
}

function hasStorage(): boolean {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

/**
 * Page-lifetime cache of the relay state.
 *
 * Read-modify-write against localStorage would race when several operations
 * run concurrently (the quick-demo flow publishes three identities at once):
 * each write would re-read a stale snapshot and the last save would win. All
 * mutations therefore happen on this one object, synchronously, and `save`
 * serialises it.
 */
let cache: RelayState | null = null;

function load(): RelayState {
  if (cache) return cache;

  if (!hasStorage()) {
    cache = { emails: [], keys: {} };
    return cache;
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<RelayState>;
      if (Array.isArray(parsed.emails) && parsed.keys && typeof parsed.keys === "object") {
        cache = { emails: parsed.emails, keys: parsed.keys };
        return cache;
      }
    }
  } catch {
    // Corrupt storage falls through to a fresh seed.
  }

  // First visit: same demo mailbox the server seeds.
  cache = { emails: demoSeedEmails(), keys: {} };
  save(cache);
  return cache;
}

function save(state: RelayState): void {
  if (!hasStorage()) return;
  try {
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ emails: state.emails.slice(-MAX_MESSAGES), keys: state.keys }),
    );
  } catch (cause) {
    console.warn("[CryptoShield] static relay could not persist:", cause);
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      // Honest marker: these bytes never left the browser.
      "x-relay": "localStorage",
    },
  });
}

/** Public-only view of a directory entry (same allowlist as the server). */
function publicView(entry: DirectoryEntry): DirectoryEntry {
  const clean: DirectoryEntry = {
    address: entry.address,
    encryptionPub: entry.encryptionPub,
    signingPub: entry.signingPub,
    fingerprint: entry.fingerprint,
    source: entry.source,
    name: entry.name,
    role: entry.role,
    createdAt: entry.createdAt,
    revoked: entry.revoked ?? false,
  };
  if (entry.revoked) {
    clean.revokedAt = entry.revokedAt;
    clean.revokeReason = entry.revokeReason;
  }
  return clean;
}

function sanitizePublicJwk(jwk: JsonWebKey): JsonWebKey {
  const clean: JsonWebKey = {
    kty: jwk.kty,
    n: jwk.n,
    e: jwk.e,
    alg: jwk.alg,
    ext: jwk.ext ?? true,
  };
  if (!clean.kty || !clean.n || !clean.e) {
    throw new Error("invalid public key: kty/n/e are required");
  }
  return clean;
}

interface KeysBody {
  action?: "revoke" | "unrevoke";
  address?: string;
  name?: string;
  role?: string;
  reason?: string;
  encryptionPub?: JsonWebKey;
  signingPub?: JsonWebKey;
}

interface EmailBody extends Partial<EmailDraft> {
  isSecureMode?: boolean;
  ciphertext?: string | null;
  symmetricKey?: string | null;
  signature?: string | null;
  senderPubKey?: SenderPublicKeys | null;
}

function parseBody(raw: unknown): Record<string, unknown> | null {
  if (raw === null || raw === undefined || raw === "") return null;
  try {
    return JSON.parse(String(raw)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** GET/POST handler for the mail relay route. */
function handleEmail(method: string, params: URLSearchParams, body: KeysBody & EmailBody): Response {
  if (method === "POST") {
    if (!body?.recipient) return json({ error: "recipient is required" }, 400);

    const isSecure = body.isSecureMode === true;
    if (isSecure && (!body.ciphertext || !body.symmetricKey || !body.signature)) {
      return json({ error: "secure message missing ciphertext / symmetricKey / signature" }, 400);
    }
    if (!isSecure && !body.body) return json({ error: "body is required" }, 400);

    const email: EmailPayload = {
      id: crypto.randomUUID(),
      sender: body.sender?.trim() || "spoofed@unverified.example",
      recipient: body.recipient.trim().toLowerCase(),
      subject: body.subject?.trim() || (isSecure ? "(end-to-end encrypted)" : "(no subject)"),
      body: isSecure ? "" : body.body ?? "",
      ciphertext: body.ciphertext ?? null,
      symmetricKey: body.symmetricKey ?? null,
      signature: body.signature ?? null,
      senderPubKey: body.senderPubKey ?? null,
      isSecureMode: isSecure,
      timestamp: Date.now(),
    };

    const state = load();
    state.emails.push(email);
    save(state);
    return json(email, 201);
  }

  // GET — mailbox listing (no auth: that IS the unsafe-mode lesson).
  const mailbox = params.get("mailbox") === "sent" ? "sent" : "inbox";
  const user = params.get("user") ?? "";
  if (!user) return json({ error: "user query param is required" }, 400);

  const field = mailbox === "sent" ? "sender" : "recipient";
  const needle = user.trim().toLowerCase();
  const emails = load()
    .emails.filter((e) => e[field].trim().toLowerCase() === needle)
    .sort((a, b) => b.timestamp - a.timestamp);
  return json(emails);
}

/** GET/POST handler for the key-directory + CRL route. */
async function handleKeys(
  method: string,
  params: URLSearchParams,
  body: KeysBody,
): Promise<Response> {
  if (method === "GET") {
    const state = load();

    if (params.get("crl")) {
      const crl: RevokedCertificate[] = Object.values(state.keys)
        .filter((e) => e.revoked)
        .map((e) => ({
          address: e.address,
          fingerprint: e.fingerprint,
          revokedAt: e.revokedAt ?? 0,
          revokeReason: e.revokeReason ?? "unspecified (demo CRL)",
        }));
      return json({ crl });
    }

    if (params.get("list")) {
      const entries = Object.values(state.keys)
        .map(publicView)
        .sort((a, b) => a.address.localeCompare(b.address));
      return json({ entries });
    }

    const address = (params.get("address") ?? "").trim().toLowerCase();
    if (!address) return json({ error: "address query param is required" }, 400);
    const entry = state.keys[address];
    if (!entry) return json({ error: `no public key registered for ${address}` }, 404);
    return json(publicView(entry));
  }

  // POST — CRL simulation or key registration.
  if (body?.action === "revoke" || body?.action === "unrevoke") {
    const address = body.address?.trim().toLowerCase();
    if (!address) return json({ error: "address is required" }, 400);
    const state = load();
    const entry = state.keys[address];
    if (!entry) return json({ error: `no certificate registered for ${address}` }, 404);

    const revoked = body.action === "revoke";
    entry.revoked = revoked;
    entry.revokedAt = revoked ? Date.now() : undefined;
    entry.revokeReason = revoked ? body.reason?.trim() || "unspecified (demo CRL)" : undefined;
    save(state);
    return json(publicView(entry));
  }

  if (!body?.address || !body.encryptionPub || !body.signingPub) {
    return json({ error: "address, encryptionPub and signingPub are required" }, 400);
  }

  try {
    const address = body.address.trim().toLowerCase();
    const encryptionPub = sanitizePublicJwk(body.encryptionPub);
    const signingPub = sanitizePublicJwk(body.signingPub);
    // Fingerprint FIRST: `state` is mutated synchronously below, so concurrent
    // registrations can't interleave between reading and writing the directory.
    const fingerprint = await jwkFingerprint(signingPub);

    const state = load();
    const previous = state.keys[address];
    const entry: DirectoryEntry = {
      address,
      encryptionPub,
      signingPub,
      fingerprint,
      source: "browser",
      name: body.name?.trim() || previous?.name,
      role: body.role?.trim() || previous?.role,
      createdAt: previous?.createdAt ?? Date.now(),
      revoked: previous?.revoked ?? false,
    };
    state.keys[address] = entry;
    save(state);
    return json({ ok: true, entry: publicView(entry), fingerprint: entry.fingerprint }, 201);
  } catch (cause) {
    return json({ error: cause instanceof Error ? cause.message : "registration failed" }, 400);
  }
}

/**
 * Drop-in replacement for `fetch` for `/api/*` in the static build.
 * Route + status codes match the Node handlers so the shared client code
 * (and its packet recording) is identical in both deployments.
 */
export async function relayFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const url = new URL(raw, hasStorage() ? window.location.origin : "http://localhost");
  const method = (init?.method ?? "GET").toUpperCase();
  const parsed = parseBody(init?.body) ?? {};
  const body = parsed as KeysBody & EmailBody;

  if (url.pathname.endsWith("/api/email")) {
    return handleEmail(method, url.searchParams, body);
  }
  if (url.pathname.endsWith("/api/keys")) {
    return await handleKeys(method, url.searchParams, body);
  }
  return json({ error: `no static relay route for ${url.pathname}` }, 404);
}
