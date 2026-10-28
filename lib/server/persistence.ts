/**
 * Tiny JSON-file persistence for the local demo backend.
 *
 * The lab must work with zero infrastructure: no database, no Docker, no
 * network. Everything the server needs (mail + the public key directory) lives
 * in `.data/cryptoshield-store.json`, which is gitignored.
 *
 * Disabled while tests run (`NODE_ENV=test`) so unit tests never touch disk.
 */

import fs from "node:fs";
import path from "node:path";
import type { EmailPayload } from "@/lib/types";

/** A published directory entry as persisted on disk (public material only). */
export interface PersistedKeyEntry {
  address: string;
  encryptionPub: JsonWebKey;
  signingPub: JsonWebKey;
  fingerprint: string;
  source: "browser" | "demo";
  name?: string;
  role?: string;
  createdAt?: number;
  revoked?: boolean;
  revokedAt?: number;
  revokeReason?: string;
}

export interface PersistedStore {
  version: 1;
  emails: EmailPayload[];
  keys: PersistedKeyEntry[];
}

const DATA_DIR = path.join(process.cwd(), ".data");
const DATA_FILE = path.join(DATA_DIR, "cryptoshield-store.json");

function persistenceEnabled(): boolean {
  return process.env.NODE_ENV !== "test" && typeof window === "undefined";
}

const EMPTY: PersistedStore = { version: 1, emails: [], keys: [] };

/** Read the persisted store (never throws — a corrupt file reads as empty). */
export function readPersistedStore(): PersistedStore {
  if (!persistenceEnabled()) return { ...EMPTY, emails: [], keys: [] };
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw) as Partial<PersistedStore>;
    return {
      version: 1,
      emails: Array.isArray(parsed.emails) ? parsed.emails : [],
      keys: Array.isArray(parsed.keys) ? parsed.keys : [],
    };
  } catch {
    return { ...EMPTY, emails: [], keys: [] };
  }
}

/**
 * Read-modify-write the store. Each domain (mail, keys) mutates only its own
 * slice, so concurrent writes can never drop the other slice.
 */
export function updatePersistedStore(mutator: (store: PersistedStore) => void): void {
  if (!persistenceEnabled()) return;
  const store = readPersistedStore();
  mutator(store);
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(store, null, 2), "utf8");
  } catch (cause) {
    // A read-only filesystem must not break the API — the in-memory state
    // still works for the lifetime of the server process.
    console.warn("[CryptoShield] could not persist demo store:", cause);
  }
}
