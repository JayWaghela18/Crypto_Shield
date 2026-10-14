/**
 * Global test setup (runs before every test file, in that file's environment).
 *
 * The crypto engine in `lib/crypto.ts` uses the platform `crypto.subtle`.
 * Node 18+ exposes it natively, but the `jsdom` environment used by the
 * sanitization suite does not implement SubtleCrypto — so we back jsdom's
 * `crypto` with Node's Web Crypto implementation. In the `node` environment
 * this is a no-op.
 */
import { webcrypto } from "node:crypto";

const existing = globalThis.crypto as Crypto | undefined;

if (!existing || typeof existing.subtle === "undefined") {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true,
    writable: true,
  });
}
