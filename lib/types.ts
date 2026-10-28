/**
 * CryptoShield — Phase 1 Data Schemas
 *
 * Single source of truth for every object that moves between the mailbox UI,
 * the API routes, and the transport inspector.
 */

/** Global security mode driving the whole app (toggle in the navbar). */
export type SecurityMode = "unsafe" | "secure";

/** Mailbox folders supported by the UI / API. */
export type MailboxFolder = "inbox" | "sent";

/** Public keys a sender publishes for the secure package (`senderPubKey`). */
export interface SenderPublicKeys {
  /** Recipient-facing RSA-OAEP public key. */
  encryption: JsonWebKey;
  /** Identity RSA-PSS public key (used to verify signatures). */
  signing: JsonWebKey;
}

/**
 * The core email document.
 *
 * Phase 1 (unsafe engine): `body` travels as raw plaintext, `sender` is taken
 * verbatim from the request (spoofable), and the crypto fields stay `null`.
 *
 * Phase 2 (secure engine): the clear-text content is replaced on the wire by
 * the hybrid envelope:
 *  - `ciphertext`  = base64(12-byte IV ‖ AES-256-GCM(payload JSON))
 *  - `symmetricKey`= base64 RSA-OAEP-256(raw AES key, recipient public key)
 *  - `signature`   = base64 RSA-PSS signature over the canonical payload bytes
 *  - `senderPubKey`= the sender's published public keys (must match the
 *                    directory registration or the message is SPOOFED)
 */
export interface EmailPayload {
  /** Server-generated unique id (crypto.randomUUID). */
  id: string;
  /** Raw From header — INTENTIONALLY unvalidated in Phase 1 (spoofing demo). */
  sender: string;
  /** Recipient address (To header). */
  recipient: string;
  /** Subject line. */
  subject: string;
  /** Body — raw HTML in unsafe mode; rendered WITHOUT sanitization (XSS demo). */
  body: string;
  /** Base64 ciphertext (null until the Phase 2 secure engine lands). */
  ciphertext: string | null;
  /** Base64 wrapped symmetric key (AES-GCM), encrypted to recipient's RSA key. */
  symmetricKey: string | null;
  /** Detached signature (RSA-PSS) over the canonical payload bytes. */
  signature: string | null;
  /** Sender's published public keys — only present on secure messages. */
  senderPubKey?: SenderPublicKeys | null;
  /** Which security mode produced this message on the sending client. */
  isSecureMode: boolean;
  /** Epoch milliseconds when the server accepted the message. */
  timestamp: number;
  /**
   * CLIENT-ONLY marker: a sender's local plaintext copy of their own sent
   * message (the server copy is opaque). Never persisted server-side — the
   * API route whitelists its fields, so this flag cannot arrive over HTTP.
   */
  localPlaintext?: boolean;
}

/* ------------------------------------------------------------------ */
/* Phase 2 — cryptographic engine schemas                               */
/* ------------------------------------------------------------------ */

/** The plaintext content protected inside a secure message. */
export interface SecurePayload {
  sender: string;
  recipient: string;
  subject: string;
  body: string;
  timestamp: number;
}

/**
 * The secure package built on send:
 * `{ payloadCiphertext, encryptedSymmetricKey, signature, senderPubKey }`
 */
export interface SecureEnvelope {
  payloadCiphertext: string;
  encryptedSymmetricKey: string;
  signature: string;
  senderPubKey: SenderPublicKeys;
}

/** Pipeline stage of a cryptographic operation (drives inspector icons). */
export type CryptoPhase =
  | "keygen"
  | "encrypt"
  | "decrypt"
  | "hash"
  | "sign"
  | "verify"
  | "sanitize"
  /** Phase 3: attacker-side step recorded by the MITM simulation. */
  | "mitm";

/** A step reported by the crypto engine before it gets an id/timestamp. */
export interface CryptoStepInput {
  phase: CryptoPhase;
  label: string;
  detail: string;
  durationMs: number;
  status: "ok" | "fail";
}

/** One finished crypto step, rendered in the transport inspector. */
export interface CryptoStep extends CryptoStepInput {
  id: string;
  timestamp: number;
}

/** Outcome of decrypting + authenticating a received secure message. */
export type VerificationStatus =
  | "pending"
  | "verified"
  /** Signature + binding OK, but the signer's certificate is on the CRL. */
  | "revoked"
  | "spoofed-tampered"
  | "spoofed-unverified"
  | "plaintext";

/** Full verification report shown next to received messages. */
export interface VerificationResult {
  status: VerificationStatus;
  /** Human-readable explanation (shown in the banner). */
  reason: string;
  /** Fingerprint of the signing key carried in the message package. */
  fingerprint?: string;
  /** Fingerprint registered in the directory for the claimed sender. */
  expectedFingerprint?: string;
  /** CRL simulation: true when the signer's certificate was revoked. */
  revoked?: boolean;
}

/** A directory entry: published public keys for one address. */
export interface DirectoryEntry {
  address: string;
  encryptionPub: JsonWebKey;
  signingPub: JsonWebKey;
  /** SHA-256 fingerprint of the signing public key (uppercase hex). */
  fingerprint: string;
  /** "browser" = registered by a live client, "demo" = server-held demo identity. */
  source: "browser" | "demo";
  /** Display name registered with the account (directory listing). */
  name?: string;
  /** Role / title registered with the account. */
  role?: string;
  /** Epoch ms when the account first registered. */
  createdAt?: number;
  /** CRL simulation: the certificate is revoked (S/MIME must reject it). */
  revoked?: boolean;
  /** Epoch ms when the certificate was revoked. */
  revokedAt?: number;
  /** Optional human-readable revocation reason (CRL "reason code"). */
  revokeReason?: string;
}

/** One entry in the simulated Certificate Revocation List. */
export interface RevokedCertificate {
  address: string;
  fingerprint: string;
  revokedAt: number;
  revokeReason: string;
}

/* ------------------------------------------------------------------ */
/* User profile schemas (keypairs + certificates)                     */
/* ------------------------------------------------------------------ */

/** An exported RSA key pair (JSON Web Key representation, `extractable: true`). */
export interface RsaKeyPairMaterial {
  /** e.g. "RSA-OAEP-256" (encryption) or "RSA-PSS" (signing). */
  algorithm: string;
  /** Key size in bits. */
  modulusLength: number;
  /** Public JWK — safe to share / embed in a certificate. */
  publicKey: JsonWebKey;
  /** Private JWK — NEVER leaves the browser, never sent to the API. */
  privateKey: JsonWebKey;
}

/** The two RSA key pairs each profile owns (encrypt + sign, like S/MIME/PGP). */
export interface UserKeyPair {
  encryption: RsaKeyPairMaterial;
  signing: RsaKeyPairMaterial;
}

/**
 * X.509-style certificate attributes.
 * Phase 1 builds a simplified self-signed structure (no ASN.1 encoding yet);
 * Phase 2 can swap in a real DER/PEM encoder without changing the schema.
 */
export interface X509LikeCertificate {
  /** Hex serial number. */
  serialNumber: string;
  /** Distinguished-name style subject, e.g. "CN=Alice, E=alice@cryptoshield.dev". */
  subject: string;
  /** Issuer DN (== subject when self-signed). */
  issuer: string;
  /** Validity window (epoch ms). */
  notBefore: number;
  notAfter: number;
  /** Base64 SPKI of the certified public key. */
  publicKeyBase64: string;
  /** SHA-256 fingerprint of the certificate (hex). */
  fingerprintSha256: string;
}

/** PGP-style certificate metadata (the "public key block" a user would publish). */
export interface PgpLikeCertificate {
  /** Packet version. */
  version: number;
  /** User ID line, e.g. "Alice <alice@cryptoshield.dev>". */
  userId: string;
  /** Creation date (epoch ms). */
  created: number;
  /** SHA-256 fingerprint of the public key (hex, grouped like PGP: A1B2...). */
  fingerprint: string;
  /** ASCII-armored placeholder block of the public key material. */
  publicKeyArmored: string;
  /** Key capabilities, e.g. ["encrypt", "sign", "certify"]. */
  keyFlags: string[];
}

/** A user profile: identity + RSA key pairs + X.509/PGP-like certificates. */
export interface UserProfile {
  /** Stable id (matches demo directory entries). */
  id: string;
  /** Human-readable name. */
  displayName: string;
  /** Primary email address. */
  email: string;
  /** Optional job title / authorization level shown in the UI. */
  role?: string;
  /** Optional avatar glyph used by the command bar. */
  avatar?: string;
  /** RSA public/private key pairs for encryption and signing. */
  keyPair: UserKeyPair;
  /** Certificates that bind the identity to the public keys. */
  certificate: {
    x509: X509LikeCertificate;
    pgp: PgpLikeCertificate;
  };
  /** When the profile was generated in this browser (epoch ms). */
  createdAt: number;
}

/* ------------------------------------------------------------------ */
/* Transport inspector schema                                          */
/* ------------------------------------------------------------------ */

/**
 * One HTTP message as it appears "on the wire" — captured by the fetch
 * wrapper in lib/api/emailClient.ts and rendered live in the inspector panel.
 */
export interface TransportPacket {
  id: string;
  /** Request leaving the browser, or response coming back. */
  direction: "outbound" | "inbound";
  method: string;
  /** Request path incl. query string, e.g. "/api/email?mailbox=inbox". */
  url: string;
  /** HTTP status (inbound packets only). */
  status?: number;
  /** Headers exactly as serialized onto the wire. */
  headers: Record<string, string>;
  /** Full body text — plaintext in unsafe mode, opaque in secure mode. */
  body: string;
  /** Body size in bytes (UTF-8). */
  sizeBytes: number;
  /** Security mode active when this packet was captured. */
  mode: SecurityMode;
  /** Capture time (epoch ms). */
  timestamp: number;
}

/** What the compose form submits (server fills in the rest of EmailPayload). */
export interface EmailDraft {
  sender: string;
  recipient: string;
  subject: string;
  body: string;
}

/**
 * GET /api/identity — the local account's public keys.
 */
export interface OwnIdentityResponse {
  user: {
    id: string;
    name: string;
    email: string;
  };
  publicKeys: SenderPublicKeys;
  /**
   * Legacy field kept for wire compatibility. This build keeps private keys in
   * the browser, so the server has no backup to return.
   */
  encryptedPrivateKey: string | null;
}

/** `GET /api/identity` before this browser has uploaded its public keys. */
export interface IdentityNotProvisionedResponse {
  needsProvisioning: true;
}

/* ------------------------------------------------------------------ */
/* Account session schemas (multi-user local accounts)                 */
/* ------------------------------------------------------------------ */

/**
 * A locally stored account: profile + private keys + the public fingerprint
 * registered in the server directory. Private keys never leave the browser.
 */
export interface LocalAccount extends UserProfile {
  role: string;
  avatar: string;
  /** SHA-256 fingerprint of the signing public key (uppercase hex). */
  fingerprint: string;
}

/** Request body accepted by `POST /api/keys` when registering an account. */
export interface RegisterAccountPayload {
  address: string;
  name: string;
  role: string;
  encryptionPub: JsonWebKey;
  signingPub: JsonWebKey;
}

/* ------------------------------------------------------------------ */
/* Phase 2 — persisted mailbox API schemas                             */
/* ------------------------------------------------------------------ */

/** A persisted message as returned by `/api/emails/*`. */
export interface MailboxMessage extends EmailPayload {
  /** Display names resolved from the User rows. */
  senderName: string;
  recipientName: string;
  /** True when the authenticated viewer is the sender. */
  sentByMe: boolean;
  /** Server-side integrity flag (Phase 3 populates it; send sets false). */
  isTampered: boolean;
}

/** Exact-match recipient lookup used before encrypting a message. */
export interface RecipientDirectoryEntry {
  user: {
    name: string;
    email: string;
  };
  publicKeys: SenderPublicKeys;
}

/** Wire payload accepted by `POST /api/emails/send`. */
export interface SendMailWirePayload {
  sender?: string;
  recipient: string;
  subject: string;
  /** Plaintext HTML (unsafe) or base64(IV‖ciphertext) (secure). */
  body: string;
  isSecureMode: boolean;
  encryptedSymmetricKey?: string;
  signature?: string;
}

/* ------------------------------------------------------------------ */
/* Security audit log schemas                                          */
/* ------------------------------------------------------------------ */

/** Classification of a detected security event. */
export type IncidentCategory =
  | "spoofing"
  | "tampering"
  | "mitm"
  | "sanitization"
  | "revoked-certificate"
  | "key-import";

export type IncidentSeverity = "critical" | "high" | "medium" | "info";

/** A detected event before it is timestamped/id'd by the audit store. */
export interface SecurityIncidentInput {
  category: IncidentCategory;
  severity: IncidentSeverity;
  /** Short headline, e.g. "Spoofed sender blocked". */
  title: string;
  /** Human-readable explanation of what was detected and why. */
  detail: string;
  sender?: string;
  recipient?: string;
  subject?: string;
  messageId?: string;
  /** Verification verdict at detection time. */
  verdict?: VerificationStatus;
  /** Extra structured context (fingerprints, sizes, reasons…). */
  meta?: Record<string, string | number | boolean>;
}

/** One entry in the exportable security incident report. */
export interface SecurityIncident extends SecurityIncidentInput {
  id: string;
  timestamp: number;
}

/** Report serialization formats offered by the inspector. */
export type IncidentReportFormat = "json" | "csv";

/* ------------------------------------------------------------------ */
/* Key management schemas (export / import)                            */
/* ------------------------------------------------------------------ */

export type KeyExportFormat = "jwk" | "pem";

/** A downloadable key artifact (content is the exact file bytes). */
export interface ExportedKeyFile {
  filename: string;
  mime: string;
  content: string;
}

/**
 * A portable key bundle used to export/import RSA material. Public-only
 * bundles are safe to share; a bundle containing private keys must stay
 * local (the demo never transmits it anywhere).
 */
export interface KeyBundle {
  /** Bundle schema version. */
  version: 1;
  /** Human-readable label ("Alice", "Bank audit", …). */
  label: string;
  /** Optional email address the keys belong to. */
  address?: string;
  exportedAt: number;
  encryptionPublic?: JsonWebKey;
  encryptionPrivate?: JsonWebKey;
  signingPublic?: JsonWebKey;
  signingPrivate?: JsonWebKey;
}

/** An externally supplied identity loaded to test third-party decryption. */
export interface ImportedIdentity {
  label: string;
  address?: string;
  /** Private key used to unwrap the AES key of a message sent to this identity. */
  encryptionPrivateKey: JsonWebKey;
  /** Optional public signing key for completeness. */
  signingPublicKey?: JsonWebKey;
  /** SHA-256 fingerprint of the imported key material. */
  fingerprint: string;
  importedAt: number;
  /** Which format the bundle was read from. */
  sourceFormat: KeyExportFormat;
}
