# CryptoShield — Troubleshooting Guide

Diagnostics for the most common errors and edge cases in the lab. Each entry
contains: the symptom, the **root cause** (why it happens), the **resolution**
(step-by-step), and the **prevention** (how to avoid it when you change the
code).

> ← Back to the [project landing page](../README.md) ·
> Related: [Setup & Run](./SETUP_AND_RUN.md) ·
> [Attack Scenarios](./ATTACK_SCENARIOS.md)

> All paths below are repository-relative. `npm run dev` runs the Next.js dev
> server at `http://localhost:3000`; the type-safe imports use the `@/*` path
> mapping in `tsconfig.json`.

---

## 1. Web Crypto API availability issues

### Symptom
- Console error: `TypeError: window.crypto.subtle is undefined` (or
  `crypto.getRandomValues is not a function`).
- `generateUserKeyPairs()` / `hybridEncrypt()` throw immediately after mount.

### Root cause
The **Web Crypto API is missing or inaccessible**. In this project that happens
when:
1. The page runs on an **outdated browser** that lacks `window.crypto.subtle`
   (e.g. old Safari/IE).

   **Note:** Unlike many Web API features, decryption/sign/verify operations do
   require a *secure context*; key generation works on `http://localhost`, but a
   plain public `http://` site may block `crypto.subtle.getRandomValues` in some
   browsers.
2. The page is served incorrectly (e.g. `file://` protocol, or a proxy that
   strips the Web Crypto shim).
3. The app is rendered **on the server** and `window` is accessed before the
   component hydrated — harmless in this codebase because all calls are gated
   behind `typeof window !== "undefined"` (`UserProfileContext` handles
   hydration via the stored profile; the in-memory store seeds server data).

### Resolution
1. Confirm you are on **http://localhost:3000** (or a real `https://` origin).
   The dev server already runs on `localhost`.
2. Update the browser to a modern, supported release.
3. If you must test from a non-localhost `http://` origin, note that some
   operations (`crypto.subtle.generateKey`) *do* work over plain HTTP in
   Chrome/Edge/Firefox today; if an operation fails, upgrade the browser or
   serve over HTTPS.
4. Verify synchronously in the browser console:
   ```js
   console.log(window.crypto.subtle ? "Web Crypto OK" : "no subtle");
   ```
5. If you added a **new async crypto call on the server side** (Next.js API
   route), use `globalThis.crypto.subtle` — Node ≥18 exposes a
   `globalThis.crypto` with `subtle`. Do **not** import Web Crypto via a
   package (`crypto` npm module is not Web Crypto).

### Prevention
- Never call `window.crypto.subtle` without guarding on `window` for the SSR
  path.
- Keep the crypto boundary in `lib/crypto.ts`; add a one-line guard at the top:
  ```ts
  if (typeof globalThis.crypto?.subtle === "undefined") {
    throw new Error("Web Crypto not available in this environment");
  }
  ```

---

## 2. RSA key import/export format errors (JWK vs SPKI/PKCS8)

### Symptom
- `DOMException: OperationError` from `crypto.subtle.importKey("jwk", ...)`.
- `exportKey("spki" / "pkcs8")` returns an `ArrayBuffer` you then pass to a
  function expecting a JWK string, or vice versa.
- "Invalid key" / "malformed JWK" messages.

### Root cause
**Format confusion.** The project deliberately works with **JWK** because
`window.crypto.subtle.importKey("jwk", ...)` is the only way to feed a full
RSA public/private key (with `n`, `e`, `d`, `p`, `q`, …) into the Web Crypto
API. Common mistakes:

| You did this | Why it fails |
| --- | --- |
| `importKey("spki", ...)` on a JWK | The API expects DER-encoded SPKI, not a JWK object. |
| `importKey("pkcs8", ...)` on a JWK | Same — SPKI/PKCS8 are DER, not JSON. |
| Passing an `ArrayBuffer` (from `exportKey("raw")`) where a **JWK object** is needed | The `jwk` format expects a `JsonWebKey` plain object, not bytes. |
| Keeping `alg: "RSA-OAEP-256"` in the JWK passed to `importKey` | Some engines reject `alg`; the code strips `alg`/`use`/`key_ops` before import. |
| Exporting with the wrong format and storing in `localStorage` | JSON stringifies a binary buffer; must go through `bytesToBase64` first. |

### Resolution
1. Identify what the key material *is*:
   - **JWK** = JavaScript `JsonWebKey` object (`{kty, n, e, d, …}`) — produced
     by `crypto.subtle.exportKey("jwk", key)` and stored in the profile.
   - **Raw** = `Uint8Array` of the key material — produced by
     `exportKey("raw", key)`; used for AES key wrapping.
   - **SPKI/PKCS8** = DER-encoded binary — `exportKey("spki" / "pkcs8", key)`.
2. Follow the conversion helpers already present in `lib/crypto.ts`:
   ```ts
   // Import JWK → CryptoKey
   const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);

   // Export CryptoKey → raw (for hybrid wrapping)
   const raw = await crypto.subtle.exportKey("raw", key); // Uint8Array
   ```
3. Never round-trip binary through JSON: use `bytesToBase64` /
   `base64ToBytes` from `lib/crypto.ts` when `localStorage` is involved.
4. If you add a **new import path**, match the algorithm params exactly —
   `importSigningKey` passes `{ name: "RSA-PSS", hash: "SHA-256" }` (the
   `saltLength` lives in the *signing* params, not in import).
5. To debug, print the JWK keys:
   ```ts
   console.log(Object.keys(jwk).sort().join(", "));
   // expected: alg, ext, key_ops, kty, n, e, d, …
   ```

### Prevention
- Centralize conversions in `lib/crypto.ts` (`importSigningKey`,
  `importWrapPublicKey`, `importWrapPrivateKey`, `jwkFingerprint`) — do not
  re-implement in components.
- Add the field-stripping step (`delete jwk.alg; delete jwk.use; delete
  jwk.key_ops`) every time you `importKey("jwk", ...)`.
- If you need a **universal key exchange** (e.g. with a real S/MIME library),
  convert DER ↔ JWK at the boundary and test both directions with a known key
  pair before wiring it into the send/receive pipeline.

---

## 3. DOMPurify sanitization stripping intended HTML tags

### Symptom
- After opening a received secure message, the body shows only text — `<b>`,
  `<i>`, `<a href>` etc. are gone, or links render as plain text.
- Secure-mode rendering shows a "stripped" count larger than expected.

### Root cause
`lib/sanitize.ts` → `sanitizeHtml()` runs **DOMPurify.sanitize()** on every
received HTML body *before* rendering in Secure Mode. DOMPurify is deliberately
strict: it removes anything it cannot prove is safe — scripts, event handlers
(`onerror`, `onclick`, `onload`), `javascript:`/`vbscript:` URLs, dangerous
elements (`<script>`, `<object>`, `<embed>`, `<iframe>` without a safe allowlist,
`<form>` with a `javascript:` action, etc.), and any attribute that could
execute code.

If your message's **source** body legitimately used any of those constructs
(e.g. a demo email with `<a href="javascript:...">` or an `<iframe>`), the
sanitizer strips them, and the UI shows the sanitized result.

### Resolution
1. Inspect what DOMPurify produced: the inspector's crypto-steps log shows a
   SANITIZE step with the detail of what was stripped. In Secure Mode the UI
   renders the sanitized string, not the raw value.
2. If you want **safe formatting** (bold, links, lists), restrict DOMPurify's
   configuration at the call site:
   ```ts
   import DOMPurify from "dompurify";
   const clean = DOMPurify.sanitize(html, {
     ALLOWED_TAGS: [...DOMPurify.defaults.ALLOWED_TAGS, "b", "i", "u", "a", "p", "br", "ul", "ol", "li"],
     ALLOWED_ATTR: [...DOMPurify.defaults.ALLOWED_ATTR, "href", "title"],
   });
   ```
3. If you truly need the raw source HTML for a demo, send it in **Unsafe
   Mode** (plaintext, intentionally unverified) — Secure Mode is designed to
   *always* sanitize.
4. Never disable sanitization in a security-sensitive route: DOMPurify is a
   filter, not an allowlist you can opt out of when the content is user
   controlled.

### Prevention
- Keep `sanitizeHtml` in one place (`lib/sanitize.ts`) and call it only on
  **received** content, never on locally composed content.
- Add a single regression test (or an Attack Lab scenario) whose body contains
  `<img src=x onerror=alert(1)>` and assert the rendered output has no
  `onerror` attribute and no alert fires.

---

## 4. Asymmetric decryption failure due to mismatched public/private key pairs

### Symptom
- Secure message: `Tampering Detected` (GCM fail), or `Decryption failed (wrong
  recipient key)`, or `INVALID SIGNATURE` on open, or the reading pane shows
  "Content unavailable".

### Root cause
**The key used to unwrap the AES key does not match the key that encrypted it.**

The secure envelope is `{ payloadCiphertext, encryptedSymmetricKey, signature,
senderPubKey }`:
- `encryptedSymmetricKey` = AES-256 key wrapped (RSA-OAEP) with the **recipient's**
  public key.
- To open it, you must unwrap with the **recipient's private key** (your own,
  if the message was addressed to `alice@cryptoshield.dev`).

Mismatches occur when:
1. The **recipient never registered its public keys** → the directory returns no
   entry → `fetchDirectoryKey` throws → message shows UNVERIFIED/plaintext.
2. The sender wrapped to the recipient's key, but the receiver tried to unwrap
   with a *different* key (e.g. a *demo* key regenerated on each server restart,
   or a browser key changed after registration).
3. The sender signed with key A, but the receiver's directory lookup returned
   key B (key-substitution). The signature check fails **before** decryption is
   even trusted, per the pipeline order.
4. A genuine *client-key rotation*: a new browser registration overwrites the
   demo entry for that address, and the envelope was encrypted to the old demo
   key.

### Resolution
1. **Check the verdict text** — it tells you the failing stage:
   - `wrong recipient key` / `unwrap` → the AES key was wrapped to another
     public key (message not addressed to this identity). Confirm the recipient
     published keys via POST `/api/keys` and reload.
   - `AES-GCM authentication failed` → unwrap **succeeded**, but the ciphertext
     was altered (MITM) — that is `Tampering Detected`, not a key problem.
   - `INVALID SIGNATURE` → signature/binding failed (Key A signed, Key B
     registered). Verify the sender's key registration.
2. **Register the correct key:**
   ```ts
   // In Secure Mode, the profile provider auto-publishes to /api/keys on mount.
   // If you are testing manually:
   fetch("/api/keys", {
     method: "POST",
     headers: { "Content-Type": "application/json" },
     body: JSON.stringify({
       address: "alice@cryptoshield.dev",
       encryptionPub: aliceEncryptionPubJwk,
       signingPub: aliceSigningPubJwk,
     }),
   });
   ```
3. **Key rotation workflow:** re-register the new public keys (POST), then
   re-send the message. Old envelopes encrypted to the previous key become
   undecryptable by design — that's the correct, secure behavior.
4. Verify the send pipeline used the *recipient's* directory key, not the
   sender's own:
   - `hybridEncrypt(payload, recipientEncPub, sender)` — the third argument is
     the sender identity used only for the signature.
5. If you modified key serialization, re-run the full handshake and confirm the
   fingerprint stored in `DirectoryEntry.fingerprint` equals the signing key's
   SHA-256 fingerprint (`jwkFingerprint`).

### Prevention
- Keep key material in one place (`UserProfileContext`); never generate a new
  pair in `keyStore.ts` for a *browser* identity — demo identities are the only
  server-side pair.
- Add an integration test that: (1) registers a pair, (2) sends an encrypted
  message to it, (3) reads it back with the matching private key, (4)
  intentionally mismatches and asserts the red verdict. This catches scenario
  #2–#4 in one run.

---

## 5. API payload body limit issues with large ciphertexts

### Symptom
- POST `/api/email` returns `413 Payload Too Large`, the server logs
  `request entity too large`, or the sent envelope arrives truncated.
- The secure envelope is ~3–4 KB for a normal message; a batch or long body
  can exceed the limit.

### Root cause
**Body-parsing limits, not cryptography.** CryptoShield uses Next.js App
Router routes (which parse JSON via the Next.js server's built-in body parser),
whose default size is intentionally small. The secure message is a JSON object
with three base64 strings (~1.33× expansion each), so a ~1–2 KB ciphertext can
already approach the limit.

If a real Express/Standalone server were used, the equivalent culprit is
`express.json({ limit: "..." })` — the same class of problem applies to any
configured limit.

### Resolution
1. **Check the actual status/code:** 413 ⇒ parse limit; 400 with `secure
   message missing ciphertext / symmetricKey / signature` ⇒ the package was
   truncated (always re-encrypt from the client rather than reusing an old
   envelope).
2. If you must send larger envelopes **without changing the demo's trust model**:
   - This is a *demo lab* — messages are tiny. The field is listed here for
     porting accuracy.
   - If you port to a real server, **raise the limit**: use a streaming body
     parser (`raw-body` / `busboy`) or set the server's max body size (e.g.
     reverse-proxy limits).
   - Better: keep payloads base64-encoded but compress first (the demo has no
     need).
   - Set a **hard reject** for anything over ~10 KB: the crypto engine should
     not silently truncate; the existing 400-checks catch the fakes.
3. Enable the server's body-size warnings in the console (Next.js prints
   `request entity too large` when the limit is hit).
4. If you keep Express: `app.use(express.json({ limit: "256kb" }))` and add a
   `413` handler that returns a JSON error used by the client.

### Prevention
- Never put secrets or streaming data in the JSON body; the demo deliberately
  keeps ciphertexts out-of-band anyway.
- Add a size guard in the client before POST: reject drafts whose base64 strings
  sum over a threshold with a clear client-side error (the current send path
  already validates required fields and reports `sendDraft` failures).
- Document the expected envelope size on the wire (the inspector shows
  `~1.3 KB` for a full envelope) so future changes can eyeball regressions.

---

## Quick reference — how to read a verdict

| `VerificationStatus` | Banner | Meaning |
| --- | --- | --- |
| `verified` | 🟩 GREEN `VERIFIED SIGNATURE` | Signature valid **and** key binding matched the directory |
| `spoofed-tampered` | 🟥 RED `TAMPERING DETECTED — SPOOFED / TAMPERED` | GCM auth failed (MITM) — or signature/structure invalid |
| `spoofed-unverified` | 🟥 RED `INVALID SIGNATURE WARNING — SPOOFED / UNVERIFIED` | Key binding failed / unknown sender — signer differs from the directory |
| `plaintext` | 🟨 AMBER `UNVERIFIED — not end-to-end encrypted` | Phase-1 plaintext (unsafe mode) or a sender-only copy |

> Always read the **reason text** under the banner (e.g. "used `…` — registered
> `…`"), then use section 4 above to map it to a fix.
