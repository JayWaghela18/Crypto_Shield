# CryptoShield — Attack Scenarios

A side-by-side walkthrough of every attack the lab simulates, what the
**Unsafe** engine does, what the **Secure** engine does, the exact payload on
the wire, and how to reproduce and verify each outcome in the browser.

The Attack Lab buttons live in `components/attacks/AttackLab.tsx`; each draft
and tamper helper lives in `lib/attacks.ts`. Every button runs in whichever
security mode is active, so the same click teaches the contrast.

> ← Back to the [project landing page](../README.md) ·
> Related: [Setup & Run](./SETUP_AND_RUN.md) ·
> [Troubleshooting](./TROUBLESHOOTING.md)

> ⚠ **Hostile code by design.** These payloads are educational and run only in
> the local lab. Never expose the app or its server to the internet.

---

## How to run an attack

1. `npm run dev` → open **http://localhost:3000**.
2. Pick a mode with the navbar toggle: **Unsafe Mode** or **Secure Mode**.
3. Click one of the three **Attack Lab** buttons:
   - **Spoofed Email Attack** (skull icon)
   - **MITM Tampering** (shuffle icon)
   - **Stored XSS Injection** (bug icon)
4. Read the inline verdict under the buttons, then open the message in the
   Inbox and watch the **Live Transport & Packet Inspector** on the right:
   the crypto-step timeline (SEND / KEYGEN / AES / WRAP / HASH / SIGN / POST /
   UNWRAP / DECRYPT / VERIFY / BIND / MITM / SANITIZE) and the wire packets.

---

## Attack 1 — Spoofed Email (`spoof`)

**Claim:** a message that *looks* like it comes from the bank, sent by someone
who does not hold the bank's private key.

**Draft** (`lib/attacks.ts → spoofedEmailDraft`):

```ts
{
  sender: SPOOF_TARGET,       // "admin@bank.com" — this client holds NO such key
  recipient: CURRENT_USER,    // "alice@cryptoshield.dev"
  subject: "URGENT: verify your bank account or it will be locked",
  body: "<p>Dear customer,</p><p>Confirm your credentials within 24 hours or your account will be suspended.</p><p>— <b>Support Team</b></p>",
}
```

| Aspect | Unsafe Mode | Secure Mode |
| --- | --- | --- |
| What the server stores | `sender` verbatim, no checks | Opaque envelope; the sender's *own* signing key is carried in `senderPubKey` |
| Signature | none | Signed with **Alice's** private key while claiming `admin@bank.com` |
| Receiver verdict | 🟨 amber `UNVERIFIED` — reads normally, no red warning | 🟥 red **INVALID SIGNATURE WARNING** — key binding fails |
| Reason shown | n/a | `used <Alice fingerprint> — registered <Bank fingerprint>` |
| Attack outcome | **Succeeds** (accepted silently) | **Blocked** (spoof detected) |

**Why Secure blocks it:** the receiver verifies the signature against the
*signer's public key*, then checks that key's fingerprint and modulus against
the directory entry for the **claimed** address (`bindSenderKey` /
`getEntry` in `lib/server/keyStore.ts`). Only the bank's real key is registered
for `admin@bank.com`, so Alice's signature cannot satisfy the binding.

**Reproduce:** click **Spoofed Email Attack**, then open the message.
- Unsafe: banner amber, `From` marked unauthenticated, body reads normally.
- Secure: banner red **INVALID SIGNATURE WARNING**, with the two fingerprints
  printed so you can see the mismatch.

---

## Attack 2 — MITM Tampering (`mitm`)

**Claim:** an attacker on the wire alters the message content in transit.

**Draft** (`lib/attacks.ts → mitmEmailDraft`): a transfer notice whose body
contains a dollar amount, e.g. `Please transfer $100 to account ACCT-12345.`

**Tamper helpers:**

| Mode | Function | What it changes |
| --- | --- | --- |
| Unsafe | `tamperPlaintext(body)` | The **first digit** of the plaintext body: `$100` → `$900` |
| Secure | `tamperCiphertext(ct)` | **One base64 character** of the ciphertext, mid-string (the attacker cannot read the payload, so it can only corrupt bytes) |

The interception is logged as a distinct red **MITM** step in the inspector
(`phase: "mitm"`, label *"MITM interception (simulated)"*), and the altered
bytes are what actually get POSTed, so the wire packet shows the tampered body.

| Aspect | Unsafe Mode | Secure Mode |
| --- | --- | --- |
| Wire form `$100 → $900` as readable JSON; edited before POST | Opaque ciphertext; 1 char flipped |
| Integrity check | **None** | AES-GCM authentication tag (a MAC over the ciphertext) |
| Receiver verdict | 🟨 amber; reads the tampered `$900` as genuine | 🟥 red **TAMPERING DETECTED** |
| Failure stage | — | AES-GCM decrypt fails **after** RSA-OAEP unwrap succeeds |
| Attack outcome | **Succeeds** (money silently changed) | **Blocked** (tamper detected) |

**Why Secure blocks it:** `decryptAndVerify` first unwraps the AES key
(RSA-OAEP with the recipient's private key). Because the wrapped key is intact,
the unwrap **succeeds** — that is the tell that this is tampering, not a key
problem. The AES-GCM decrypt then fails its authentication tag because one
ciphertext byte changed, and the pipeline reports `Tampering Detected`.

> **Note:** the "interception" is a client-side relay simulation — there is no
> real proxy in the demo. The one-character alteration happens in
> `MailStoreContext.sendDraft` (`options.tamper`) between `hybridEncrypt` and
> the POST.

**Reproduce:** click **MITM Tampering**.
- Unsafe: open the message — the amount is wrong but presented as authentic.
- Secure: open the message — red **TAMPERING DETECTED**; the inspector shows
  the red ATTACK step and a failed GCM check.

---

## Attack 3 — Stored XSS Injection (`xss`)

**Claim:** a script hidden in an email body executes in the reader's session
when the message is opened — the classic **stored** XSS.

**Draft** (`lib/attacks.ts → xssEmailDraft`):

```html
<p>Click to claim your prize.</p>
<img src="x"
     onerror="alert('⚠ STORED XSS — session hijacked (simulated): your cryptoshield session cookie was stolen');
              document.title='XSS_SESSION_HIJACKED'">
```

The payload is sent **from the current user to the current user** on purpose:
in Secure Mode this makes the signature verify (green), so the *only* thing
standing between the script and execution is **DOMPurify** — exactly the
contrast this scenario is meant to show.

| Aspect | Unsafe Mode | Secure Mode |
| --- | --- | --- |
| Stored form | Raw HTML `body` verbatim | Ciphertext; HTML only recovered after decrypt |
| Render path | `EmailBody` injects raw HTML (`dangerouslySetInnerHTML`) | `lib/sanitize.ts → sanitizeHtml()` (DOMPurify) runs first |
| Signature verdict | 🟨 amber `UNVERIFIED` | 🟩 green `VERIFIED SIGNATURE` |
| Sanitize step | none | logged: `onerror` handler stripped |
| Result | 🔥 `alert()` fires; `document.title` becomes `XSS_SESSION_HIJACKED` | ✅ no alert; handler removed before render |
| Attack outcome | **Succeeds** (session hijack simulated) | **Blocked** (script stripped) |

**Why Secure blocks it:** after successful decryption and signature
verification, `sanitizeHtml` runs the recovered HTML through DOMPurify, which
removes the `onerror` attribute (and any other event handler, script, or
`javascript:` URL) before the body is rendered. The script never reaches the
DOM.

**Reproduce:** click **Stored XSS Injection**, then open the message.
- Unsafe: an `alert()` banner fires and the tab title changes — the classic
  stored-XSS marker.
- Secure: no alert; the inspector shows the SANITIZE step, and the signature is
  still green (proving the defense is sanitization, not the crypto).

---

## Attack vector comparison matrix

| Scenario | Unsafe Mode | Secure Mode | Demonstrated by |
| --- | --- | --- | --- |
| **Email spoofing** | Accepted silently — `From` stored verbatim, no key checked | 🟥 **Invalid Signature Warning** — signing key ≠ directory key for the claimed address | Attack Lab "Spoofed Email Attack" |
| **Plaintext sniffing** | Full read — body travels as raw HTML on the wire | Opaque envelope — observers see ciphertext + wrapped key + signature only | Inspector wire panel (mode label + body bytes) |
| **MITM tampering** | Reads normally — no integrity check; `$100 → $900` accepted | 🟥 **Tampering Detected** — AES-GCM authentication tag fails (unwrap succeeded) | Attack Lab "MITM Tampering" |
| **Stored XSS** | Script executes — `<img onerror>` runs in the reader's session | ✅ Safe — DOMPurify strips the handler; alert never fires | Attack Lab "Stored XSS Injection" |
| **Key substitution** | — | 🚫 Blocked — binding compares the message key to the directory entry | Spoofed case shows `used X — registered Y` |
| **Unknown sender** | — | 🟨 Unverified — no directory entry for the claimed address | Bootstrap case |
| **Message replay** | Possible — no freshness/sequencing | Not modeled (out of scope for this lab) | — |

---

## Expected verdict quick-lookup

| Attack | Unsafe Mode verdict | Secure Mode verdict |
| --- | --- | --- |
| Spoofed Email | 🟨 `UNVERIFIED — not end-to-end encrypted` | 🟥 `INVALID SIGNATURE WARNING` |
| MITM Tampering | 🟨 reads tampered text as genuine | 🟥 `TAMPERING DETECTED` |
| Stored XSS | 🟨 executes (alert fires) | 🟩 `VERIFIED SIGNATURE` + handler stripped |

> Full verdict semantics and how to map a failing stage to a fix are in the
> [Troubleshooting guide](./TROUBLESHOOTING.md#quick-reference--how-to-read-a-verdict).
