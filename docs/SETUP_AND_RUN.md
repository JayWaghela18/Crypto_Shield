# CryptoShield — Setup & Run

Everything below is for a **local development or production build** of the
CryptoShield demo lab. No build tooling beyond Node 18+ is required; the
application stores no secrets and reads no environment variables at runtime
(cryptography uses the native `window.crypto.subtle` and the in-memory server
database).

> ← Back to the [project landing page](../README.md) ·
> Related: [Troubleshooting](./TROUBLESHOOTING.md) ·
> [Attack Scenarios](./ATTACK_SCENARIOS.md)

---

## 1. Prerequisites

| Requirement | Minimum version | Notes |
| --- | --- | --- |
| **Node.js** | 18.0.0 | `window.crypto.subtle` is used in the browser; the Node 18+ built-in `crypto.subtle` is used by the API routes. Node 20 LTS is recommended for `npx` convenience. |
| **npm** | 9.0+ (ships with Node 18+) | `package-lock.json` is committed; keep it in sync with `npm install`. |
| **Browser** | Modern (Chrome/Edge/Firefox/Safari) | Required for `window.crypto.subtle` and `crypto.getRandomValues`. |
| **git** | Any recent | Only needed if you clone the repo. |

> ℹ **Non-HTTPS / non-localhost caveats:** The Web Crypto API is available in
> all modern browsers even on `http://localhost` (the demo is designed to run
> locally). If you later publish this to a public domain, browsers will still
> allow `crypto.subtle` (it is neither a secure context requirement for
> *generating* keys, though some operations like `navigator.credentials` would
> be). CryptoShield intentionally keeps cryptography to `window.crypto.subtle`
> so it works on plain `http://localhost` without HTTPS.

---

## 2. Environment variables

**There are none.** CryptoShield is a zero-secret demo:

- No `.env`, no API keys, no database credentials.
- Private keys never leave the owner's browser.
- The server keeps only an in-memory relay + public-key directory.

If you extend the lab with a third-party service, add a `.env.local`
(git-ignored) and document each variable here. Nothing in the current code
reads `process.env`.

---

## 3. Clone and install

```bash
# 1. Clone (or cd into the project folder)
git clone https://github.com/JayWaghela18/Block-chain-workshop.git   # repo as provided
cd Block-chain-workshop                                    # or the folder you named

# 2. Install dependencies (respects the locked versions in package-lock.json)
npm install

# 3. Quick sanity check (type check only — no emit)
npm run typecheck
```

`package.json` scripts are:

```json
{
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "typecheck": "tsc --noEmit",
    "lint": "next lint",
    "test": "vitest run",
    "test:watch": "vitest"
  }
}
```

---

## 4. Start the development server

```bash
npm run dev
```

Dev server: **http://localhost:3000** (Next.js default port; change with
`npm run dev -- -p 4200` if 3000 is taken).

What you'll see:
- **Left** — the split mailbox: Inbox / Sent / Compose tabs + reading pane.
- **Right** — the Live Transport & Packet Inspector (crypto-step timeline
  + wire packets), plus the **Attack Lab** strip above the tabs.
- The security mode switch in the navbar (`Unsafe Mode` ↔ `Secure Mode`).

First load takes a few seconds: the browser generates an RSA-2048 key pair,
builds the X.509/PGP-like certificates, and registers the public keys with
`/api/keys` (the "published key" for `alice@cryptoshield.dev` appears in the
directory). No server-side state is required — the in-memory database seeds a
few demo messages.

### Useful dev commands

```bash
npm run typecheck   # tsc --noEmit — catch type errors before the build
npm run lint        # next lint — ESLint over app/components/lib
npm test            # vitest run — crypto + attack unit tests
npm run build       # production build (type-checked + linted)
npm run start       # run the production build (http://localhost:3000)
```

### Automated tests

The suite lives in `tests/` and runs with **Vitest**:

- `tests/crypto.test.ts` — key generation (RSA-OAEP / RSA-PSS), AES-256-GCM
  round-trip, and single-character tamper detection (node environment).
- `tests/attacks.test.ts` — spoofed-sender signature verification failures and
  DOMPurify sanitization before DOM insertion (jsdom environment).

The same checks run on every push and pull request via
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

---

## 5. Production build

```bash
npm run build
```

What the build produces:
- **`.next/`** — the server-rendered app (API routes compiled to JS).
- **`.next/static/`** — client JS/CSS chunks and the static assets.
- **`out/`** is *not* used — Next.js App Router builds a server (`.next/`),
  which is what the ready `npm run start` serves.

Then run it:

```bash
npm run start
```

and open **http://localhost:3000** (or wherever `next start` reports it).

### Public-facing deployment notes
- The server **has no secrets**: no API keys, no database credentials, no
  private keys anywhere on the server (demo identities' private keys are
  non-extractable and used only to *sign* a welcome message).
- The directory lookup and registration endpoints do **not** require
  authentication — this is by design for a demo, and the README marks it
  "educational only". Do not expose the app to the public internet.
- `npm run build` is the only command required for a server-rendered
  deployment (no static export). `output: 'export'` is not supported with the
  App Router / Web Crypto usage.

---

## 6. Project folder map

```
CryptoShield/
│
├── app/                          # Next.js App Router
│   ├── page.tsx                  # Home: split-screen shell (Mailbox | Inspector)
│   ├── layout.tsx                # Providers + global styles
│   ├── globals.css               # Tailwind base / theme
│   └── api/
│       ├── email/route.ts        # SEND (POST) / RECEIVE (GET ?mailbox=&user=)
│       │                           - unsafe: stores plaintext {sender,subject,body}
│       │                           - secure: stores opaque envelope {ciphertext,
│       │                             symmetricKey, signature, senderPubKey}
│       └── keys/route.ts           # Directory: GET ?address= → public keys,
│                                     #         POST → register (public material only)
│
├── components/
│   ├── attacks/AttackLab.tsx     # 3 attack trigger buttons + outcome narration
│   ├── inspector/TransportInspector.tsx
│   │                               # Crypto step timeline + wire packet viewer
│   ├── inspector/IncidentReportButton.tsx
│   │                               # Download security incident report (JSON/CSV)
│   ├── keys/KeyManager.tsx         # Export/import RSA keys + CRL inspector
│   ├── mailbox/
│   │   ├── Mailbox.tsx               # Inbox / Sent / Compose + reading pane
│   │   ├── ComposeForm.tsx           # Spoofable From-field compose UI
│   │   ├── EmailBody.tsx             # Raw HTML (unsafe) / DOMPurify sanitized (secure)
│   │   ├── useSecureMessage.ts       # Receive pipeline: decrypt → verify → CRL → sanitize
│   │   ├── VerificationBanner.tsx    # VERIFIED / SPOOFED / TAMPERED / REVOKED / UNVERIFIED
│   │   ├── CertificateStatusControl.tsx  # CRL toggle (revoke / reinstate a sender)
│   │   └── ExternalDecryptPanel.tsx  # Try decryption with an imported third-party key
│   ├── Navbar.tsx                  # Branding, mode status, identity badge
│   └── SecurityModeToggle.tsx        # Mode switch (unsafe ↔ secure)
│
├── lib/
│   ├── crypto.ts                     # Hybrid encryption + signing + receive pipeline
│   │                                   (AES-256-GCM, RSA-OAEP, RSA-PSS, SHA-256)
│   ├── crypto/webcrypto.ts           # Key generation, X.509/PGP-like certificates
│   ├── sanitize.ts                   # DOMPurify helper (client-side only)
│   ├── api/emailClient.ts            # fetch wrappers recording on-the-wire packets
│   ├── attacks.ts                    # Attack drafts + tamper helpers
│   ├── keys/
│   │   ├── pem.ts                    # JWK ⇄ PEM (SPKI/PKCS#8) conversion
│   │   └── bundle.ts                 # Key bundle export/import + import-identity builder
│   ├── audit/
│   │   ├── classify.ts               # Verification verdict → security incident
│   │   └── report.ts                 # Incident report JSON/CSV serialization
│   ├── download.ts                   # Client-side file download helper
│   ├── types.ts                      # Schemas: EmailPayload, SecureEnvelope,
│   │                                   DirectoryEntry, VerificationResult, …
│   ├── server/
│   │   ├── memoryStore.ts            # In-memory email database (server-side)
│   │   └── keyStore.ts               # Public key directory + demo identities
│   └── constants.ts                  # CURRENT_USER, DEMO_USERS (incl. admin@bank.com),
│                                       # SPOOF_TARGET
│
├── store/                          # React Context providers
│   ├── AppProviders.tsx              # Composes all providers
│   ├── SecurityModeContext.tsx         # Global unsafe/secure mode
│   ├── TransportContext.tsx            # Wire packets + crypto-step log
│   ├── MailStoreContext.tsx            # Mailbox state + send/load + tamper hook
│   ├── AuditContext.tsx                # Detected-incident log + report export
│   ├── KeyVaultContext.tsx             # Imported third-party key material
│   └── UserProfileContext.tsx          # Profile + key pair + directory registration
│
├── docs/                           # ← this folder
│   ├── SETUP_AND_RUN.md
│   ├── TROUBLESHOOTING.md
│   └── ATTACK_SCENARIOS.md
│
├── tests/                          # Vitest suite
│   ├── setup.ts                      # ensures crypto.subtle in every env
│   ├── crypto.test.ts                # keygen / AES-GCM round trip / tampering
│   └── attacks.test.ts               # spoof verification + DOMPurify
│
├── .github/workflows/ci.yml        # CI: typecheck, lint, tests, build
├── vitest.config.ts                # test runner + @/* alias
├── .eslintrc.json                  # ESLint (next/core-web-vitals)
│
├── package.json
├── package-lock.json
├── tsconfig.json
├── tailwind.config.ts
├── postcss.config.mjs
├── next.config.mjs
└── next-env.d.ts
```

**Where each concern lives**

| Concern | Files |
| --- | --- |
| Frontend UI | `app/`, `components/`, `store/` |
| Backend API (routes) | `app/api/email/route.ts`, `app/api/keys/route.ts` |
| Crypto engine | `lib/crypto.ts`, `lib/crypto/webcrypto.ts` |
| Sanitization | `lib/sanitize.ts` |
| Key directory + demo identities | `lib/server/keyStore.ts` |
| Message database | `lib/server/memoryStore.ts` |
| Transport recording | `lib/api/emailClient.ts` |
| Attack simulations | `lib/attacks.ts`, `components/attacks/AttackLab.tsx` |
| Key management | `lib/keys/pem.ts`, `lib/keys/bundle.ts`, `components/keys/KeyManager.tsx` |
| Security audit log | `lib/audit/classify.ts`, `lib/audit/report.ts`, `store/AuditContext.tsx` |
| Certificate revocation (CRL) | `lib/server/keyStore.ts` (`setRevocation`/`listRevoked`), `lib/crypto.ts`, `components/mailbox/CertificateStatusControl.tsx` |

---

## 7. Verify your install

```bash
npm run typecheck   # ✓ should exit 0
npm run lint        # ✓ should report no warnings/errors
npm test            # ✓ 59 tests should pass
npm run build       # ✓ should exit 0
npm run dev         # ✓ http://localhost:3000 renders the mail lab
```

Then, in a supported browser:
1. Switch to **Secure Mode** (nav bar).
2. Click **Stored XSS Injection** in the Attack Lab — the narration says
   `SIMULATION BLOCKED — DEFENDED`; opening the retrieved message never fires
   the script.
3. Click **Spoofed Email Attack** — the message is accepted in Unsafe mode and
   shows **INVALID SIGNATURE WARNING** in Secure mode.
4. Click **MITM Tampering** — Secure shows `Tampering Detected` (red ATTACK
   step in the inspector), Unsafe reads the tampered text silently.

Full expected outcomes per attack are documented in
[ATTACK_SCENARIOS.md](./ATTACK_SCENARIOS.md).

---

## 8. Troubleshooting (short reference)

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `window.crypto.subtle is undefined` | Browser without Web Crypto (old IE) or a non-secure context for some operations | Use a modern browser on `http://localhost` (both OK here). See [TROUBLESHOOTING §1](./TROUBLESHOOTING.md#1-web-crypto-api-availability-issues). |
| RSA import fails with `OperationError` | JWK has unexpected fields (`alg` / `use` / `key_ops` kept) | The import helpers strip those fields first; only pass `name`/`hash`/`saltLength` to `importKey`. See [TROUBLESHOOTING §2](./TROUBLESHOOTING.md#2-rsa-key-importexport-format-errors-jwk-vs-spkipkcs8). |
| Secure send fails with `400` | Missing fields (`ciphertext`/`symmetricKey`/`signature`) | The **Secure Mode** engine must complete `hybridEncrypt` before POST. |
| Secure message shows `UNVERIFIED` after reload | Profile not loaded or not yet registered | Wait for profile `ready` + directory registration; the inbox then refreshes. |
| Wrong recipient key unwrap error | Message encrypted to a different directory key | Sender's `hybridEncrypt` used the recipient's directory key — confirm the recipient published keys to `/api/keys` first. See [TROUBLESHOOTING §4](./TROUBLESHOOTING.md#4-asymmetric-decryption-failure-due-to-mismatched-publicprivate-key-pairs). |
| `Tampering Detected` on your own sent mail | GCM tag failed; unwrap succeeded | That **is** the MITM detection — expected behavior; the unwrap-success-vs-GCM-failure split in `decryptAndVerify` is what distinguishes it. |
| Large ciphertext POST truncated / `413` | App-level body limit, not cryptography | N/A for this lab (message sizes are tiny). If porting, watch `body-parser` limits. See [TROUBLESHOOTING §5](./TROUBLESHOOTING.md#5-api-payload-body-limit-issues-with-large-ciphertexts). |
