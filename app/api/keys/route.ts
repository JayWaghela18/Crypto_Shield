/**
 * /api/keys — the public key directory + simulated CRL (trust roots).
 *
 * GET  /api/keys?address=x      → published public keys for an address
 * GET  /api/keys?list=1         → every registered address (recipient picker)
 * GET  /api/keys?crl=1          → the simulated Certificate Revocation List
 * POST /api/keys                → a client publishes its own public keys
 *                                  (public material ONLY; private keys are
 *                                  rejected by field allowlisting)
 * POST /api/keys {action:"revoke"|"unrevoke", address, reason?}
 *                               → CRL simulation: revoke / reinstate a cert
 *
 * ⚠ This directory is the ROOT OF TRUST for the anti-spoofing demo: a
 * signature only proves identity if the verifying key is looked up HERE,
 * never if it comes from the message itself.
 */

import { NextResponse } from "next/server";
import {
  getEntry,
  listEntries,
  listRevoked,
  registerBrowserKeys,
  setRevocation,
} from "@/lib/server/keyStore";

const NO_STORE = { "Cache-Control": "no-store" } as const;

/** LOOKUP — published public keys, the address list, or the whole CRL. */
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);

  // Simulated Certificate Revocation List.
  if (searchParams.get("crl")) {
    return NextResponse.json({ crl: listRevoked() }, { headers: NO_STORE });
  }

  // Full directory listing (used by compose + the account switcher).
  if (searchParams.get("list")) {
    const entries = await listEntries();
    return NextResponse.json({ entries }, { headers: NO_STORE });
  }

  const address = searchParams.get("address") ?? "";

  if (!address) {
    return NextResponse.json({ error: "address query param is required" }, { status: 400 });
  }

  const entry = await getEntry(address);
  if (!entry) {
    return NextResponse.json(
      { error: `no public key registered for ${address}` },
      { status: 404 },
    );
  }

  return NextResponse.json(entry, { headers: NO_STORE });
}

interface KeysBody {
  /** Optional action discriminator; omitted ⇒ key registration. */
  action?: "revoke" | "unrevoke";
  address?: string;
  name?: string;
  role?: string;
  reason?: string;
  encryptionPub?: JsonWebKey;
  signingPub?: JsonWebKey;
}

/** REGISTER keys + account metadata, or toggle a certificate's CRL status. */
export async function POST(request: Request) {
  let body: KeysBody;
  try {
    body = (await request.json()) as KeysBody;
  } catch {
    return NextResponse.json({ error: "Request body must be valid JSON" }, { status: 400 });
  }

  // ── CRL simulation: revoke / reinstate ────────────────────────────
  if (body.action === "revoke" || body.action === "unrevoke") {
    if (!body.address) {
      return NextResponse.json({ error: "address is required" }, { status: 400 });
    }
    const entry = await setRevocation(
      body.address,
      body.action === "revoke",
      body.reason,
    );
    if (!entry) {
      return NextResponse.json(
        { error: `no certificate registered for ${body.address}` },
        { status: 404 },
      );
    }
    return NextResponse.json(entry);
  }

  // ── Account / key registration ────────────────────────────────────
  if (!body.address || !body.encryptionPub || !body.signingPub) {
    return NextResponse.json(
      { error: "address, encryptionPub and signingPub are required" },
      { status: 400 },
    );
  }

  try {
    const entry = await registerBrowserKeys(
      body.address,
      body.encryptionPub,
      body.signingPub,
      { name: body.name, role: body.role },
    );
    return NextResponse.json(
      { ok: true, entry, fingerprint: entry.fingerprint },
      { status: 201 },
    );
  } catch (cause) {
    return NextResponse.json(
      { error: cause instanceof Error ? cause.message : "registration failed" },
      { status: 400 },
    );
  }
}
