# 🛡 CryptoShield

**An interactive, in-browser lab that shows, side by side, how email breaks
without cryptography and how end-to-end encryption + signatures stop the same
attacks.**

Spoofing, plaintext sniffing, MITM tampering, and stored XSS on one side;
AES-256-GCM confidentiality, RSA-OAEP key wrapping, RSA-PSS signatures,
directory key-binding, and DOMPurify sanitization on the other. Flip a single
toggle and watch the same attack succeed or get blocked — live, in the
transport inspector.

![Next.js](https://img.shields.io/badge/Next.js-14-000000?logo=nextdotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)
![Web Crypto API](https://img.shields.io/badge/Web%20Crypto%20API-native-4B8BBE?logo=webcrypto&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind%20CSS-3-06B6D4?logo=tailwindcss&logoColor=white)
![Build](https://img.shields.io/badge/build-passing-2EA043?logo=githubactions&logoColor=white)

> ⚠ **EDUCATIONAL DEMO ONLY.** The "unsafe" engine is intentionally insecure
> (spoofable `From`, raw HTML rendering, no auth). Run it locally
> (`npm run dev`) and never expose it to the internet.

---

## ⚡ 30-second quickstart

```bash
npm install        # install dependencies
npm run dev        # start the lab → http://localhost:3000
```

Then: flip the navbar toggle to **Secure Mode**, and click the three buttons in
the **Attack Lab** — *Spoofed Email*, *MITM Tampering*, *Stored XSS*. Open each
message and compare the banner verdict against **Unsafe Mode**.

No `.env`, no API keys, no third-party crypto packages — just Node 18+ and a
modern browser. Every script, port and gotcha is listed under
[🚀 Run the project](#-run-the-project) below.

📚 **Full documentation lives in [`/docs`](./docs):**

| Doc | What's inside |
| --- | --- |
| [**SETUP_AND_RUN.md**](./docs/SETUP_AND_RUN.md) | Prerequisites, install/run/build commands, env-var story, full folder map |
| [**DEPLOYMENT.md**](./docs/DEPLOYMENT.md) | Step-by-step GitHub Pages publish, static build internals, server-deploy alternative |
| [**TROUBLESHOOTING.md**](./docs/TROUBLESHOOTING.md) | Web Crypto availability, JWK vs SPKI/PKCS8, DOMPurify stripping, key mismatch, body limits |
| [**ATTACK_SCENARIOS.md**](./docs/ATTACK_SCENARIOS.md) | Every attack payload, expected verdicts, and reproduction steps |

---

## 🚀 Run the project

```bash
# 1. Install dependencies (Node 18+, 20 LTS recommended)
npm install

# 2. Start the dev server → http://localhost:3000
npm run dev

# 3. (optional) verify everything
npm run typecheck   # tsc --noEmit
npm test            # vitest — crypto + attack suite
npm run lint        # eslint (next/core-web-vitals)
npm run build       # production server build (type-checked + linted)
npm run start       # run that build on http://localhost:3000
```

| Script | What it does |
| --- | --- |
| `npm run dev` | Clears `.next/` first (avoids the OneDrive/`readlink` crash), then starts `next dev` on port 3000 |
| `npm run dev:keep` | Plain `next dev` without the pre-clean |
| `npm run build` | Normal **server** build — real `/api/email` + `/api/keys` routes |
| `npm run build:static` | **Static** build for GitHub Pages → `./out` (API routes swapped for the localStorage relay) |
| `npm run preview:static` | Serve `./out` locally on http://localhost:4173 |
| `npm run typecheck` / `lint` / `test` | tsc · eslint · vitest |

Then: flip the navbar toggle to **Secure Mode**, and click the three buttons in
the **Attack Lab** — *Spoofed Email*, *MITM Tampering*, *Stored XSS*. Open each
message and compare the banner verdict against **Unsafe Mode**.

> If port 3000 is busy: `npm run dev -- -p 4200`.
> If a build ever fails with `EINVAL … readlink … .next`, just run
> `npm run dev` again — it removes the stale `.next` folder automatically.

---

## 🌐 Deploy to GitHub Pages

```bash
npm run build:static     # static bundle → ./out
npm run preview:static   # check it at http://localhost:4173
```

**Go live (already wired up):**

1. GitHub → **Settings → Pages → Source → GitHub Actions**.
2. `git push origin main` — the included
   [`deploy-pages.yml`](./.github/workflows/deploy-pages.yml) workflow builds
   `out/` with `NEXT_PUBLIC_BASE_PATH=/<repo>` and publishes it.
3. Open the URL from the Actions run:
   `https://jaywaghela18.github.io/Crypto_Shield/`

**Read this first:** GitHub Pages has no Node server, so `/api/email` and
`/api/keys` are replaced by a **localStorage relay**
([`lib/api/staticRelay.ts`](./lib/api/staticRelay.ts)) — same routes, same
validation, same client-side cryptography, but each visitor's demo data lives
in their own browser. Want one shared inbox for everyone? Deploy `npm run
build` + `npm start` to any Node host instead.

Full walkthrough, troubleshooting and a pre-publish checklist:
[**docs/DEPLOYMENT.md**](./docs/DEPLOYMENT.md).

---

## 🔐 Crypto sequence — key generation → encrypt → sign

```
  BROWSER (client)                          SERVER (/api/keys, /api/email)     RECEIVER (browser)
  ─────────────────────────────             ──────────────────────────────     ─────────────────────
  ① KEY GENERATION (once, on load)
  ┌─────────────────────────────────┐
  │ crypto.subtle.generateKey       │  RSA-OAEP    → encryption key pair
  │   ├─ RSA-OAEP  (wrap/unwrap)    │  RSA-PSS     → signing key pair
  │   └─ RSA-PSS   (sign/verify)    │  (private half NEVER leaves the browser)
  └─────────────────────────────────┘
              │  public keys only
              ▼                                        ┌──────────────────────┐
  ┌─────────────────────────────────┐  POST /api/keys │  Directory           │
  │  register public keys +         │────────────────▶│  address → {pubE,    │
  │  SHA-256 fingerprint            │                 │   pubS, fingerprint} │
  └─────────────────────────────────┘                 └──────────┬───────────┘
                                                                  │ GET ?address=<recipient>
  ② ENCRYPT (per message)                                         ▼
  ┌─────────────────────────────────┐                 ┌──────────────────────┐
  │ AES-256-GCM:                     │                 │  recipient's public  │
  │   key   = crypto.getRandomValues │◀────────────────│  encryption key      │
  │   iv    = 12 random bytes        │                 └──────────────────────┘
  │   ct    = AES-GCM(payload, iv)   │
  └─────────────────────────────────┘
  ③ SIGN (per message)
  ┌─────────────────────────────────┐
  │ digest = SHA-256(canonical)      │   canonical bytes = {sender, recipient,
  │ sig    = RSA-PSS(digest, privS)  │                       subject, body, timestamp}
  └─────────────────────────────────┘   (fixed key order — both sides hash identically)
  ④ WRAP + POST (opaque envelope only — no plaintext on the wire)
  ┌─────────────────────────────────┐  POST /api/email
  │ wrappedKey = RSA-OAEP(aesKey,     │────────────────▶  relay stores opaque bytes
  │                         rpubE)   │                    (cannot decrypt or read)
  └─────────────────────────────────┘                                        │
                │                                                             ▼
                │                          ┌──────────────────────────────────────────┐
                │                          │ ⑤ UNWRAP  RSA-OAEP(wrappedKey, privE)     │
                │                          │ ⑥ DECRYPT AES-256-GCM  → payload           │
                │                          │ ⑦ VERIFY  RSA-PSS(sig, directory pubS)      │
                │                          │ ⑧ BIND    signer fingerprint == directory? │
                │                          │ ⑨ SANITIZE  DOMPurify before render         │
                │                          └──────────────────────────────────────────┘
                ▼
     VERDICT:  🟩 VERIFIED   🟥 SPOOFED / TAMPERED   🟨 UNVERIFIED (plaintext)
```

The private keys, the plaintext, and the AES key never leave the client. The
server is a dumb relay — it cannot forge, decrypt, or even read a secure
message by design.

---

## 🧱 Key architectural takeaways

**Why the native Web Crypto API instead of a third-party Node crypto package?**

- **Single primitive set, two runtimes.** The exact same `crypto.subtle`
  surface (`generateKey`, `importKey`, `encrypt`, `decrypt`, `sign`, `verify`,
  `digest`, `getRandomValues`) in `lib/crypto.ts` runs in the browser *and* in
  Node 18+ API routes — no Node-only `crypto` module, no browser-only shim, no
  conditional imports. That is what lets the app be 100% client-side for key
  material while still type-checking against one implementation.
- **Private keys are non-exportable by construction.** Beyond the demo's own
  care, `CryptoKey` objects can be created with `extractable: false`, and
  sensitive material simply never has to be serialized to a buffer the app can
  leak. A JSON-oriented JS library would hand you raw key bytes by default.
- **Zero dependencies = zero supply-chain surface for the security core.**
  The entire trust boundary is browser/Node-native code, so there is no
  third-party crypto package to audit, version-bump, or worry about a
  compromised release. `dompurify` is the only security-adjacent dependency,
  and it is limited to the client-side render path.
- **Browser-enforced secure-context semantics.** Web Crypto refuses to operate
  outside a secure context, so the app inherits the platform's own guarantees
  rather than re-implementing them — a class of bug you cannot accidentally
  ship.
- **No key-format ambiguity at the boundary.** Working in **JWK** throughout
  (`importKey("jwk", …)`) keeps fixtures readable and diffable in the inspectable
  profile, while `bytesToBase64`/`base64ToBytes` handle the one unavoidable
  binary hop (AES key wrapping).
- **It is itself the lesson.** The module-alignment goal — demonstrating AES-256-GCM,
  RSA-OAEP, RSA-PSS, and SHA-256 — is more honest when those primitives come
  from the platform the user actually browses with, not from a package that
  hides them.

Other structural choices worth knowing:

- **Single-page App Router shell** — one `app/page.tsx` composes a Mailbox on
  the left and a Live Transport Inspector on the right, so every crypto step is
  visible as it happens.
- **Context-driven state** — `SecurityModeContext` flips the whole pipeline,
  `TransportContext` records wire packets + crypto-step timelines,
  `MailStoreContext` runs send/receive, `UserProfileContext` owns key material.
- **Trust root = the directory.** A signature only counts if the signing key's
  fingerprint matches the published entry for the *claimed* address —
  anti-key-substitution by design.
- **Two engines, one UI.** The unsafe engine is deliberately insecure so the
  contrast is honest; the secure engine is the real hybrid scheme.

---

## 🧰 Advanced key & audit tooling

Beyond the send/receive lab, CryptoShield ships three management surfaces:

- **Key Management (`Keys` in the navbar)** — export this browser's RSA key
  pairs as **JWK** or **PEM** (SPKI public / PKCS#8 private), and **import**
  external key material to test third-party decryption. Imported keys drive a
  "try decrypting with imported key" action in the reading pane, which shows
  exactly which pipeline stage rejects a message that wasn't addressed to it.
- **Security Incident Report (inspector header)** — every detected attack is
  classified and logged: spoofing, MITM/tampering, XSS sanitization, revoked
  certificates (plus simulated interceptions and key-import attempts). The
  `Report` button exports the log as structured **JSON** or **CSV**.
- **CRL simulation (reading pane, Secure Mode)** — revoke a sender's
  certificate and watch S/MIME verification reject the message **even though
  the RSA-PSS signature is mathematically valid**. Revocation never touches key
  material; the verification pipeline consults the revocation list separately.

---

## 🗂 Project at a glance

| Area | Technology |
| --- | --- |
| Frontend | Next.js 14 (App Router), React 18, Tailwind CSS, Lucide Icons |
| Backend | Next.js API Routes — `/api/email` (relay), `/api/keys` (directory) |
| Cryptography | Native Web Crypto API — RSA-OAEP, RSA-PSS, AES-256-GCM, SHA-256 |
| Sanitization | DOMPurify (secure-mode render path only) |
| State | React Context (mode, transport, mail, profile) |

See [SETUP_AND_RUN.md §6](./docs/SETUP_AND_RUN.md#6-project-folder-map) for the
full folder map.

---

## 📎 License / intent

Built as a teaching artifact. Reuse the *patterns*, not the unsafe engine.
