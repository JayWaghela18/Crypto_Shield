import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

/**
 * CryptoShield test runner.
 *
 * - `@/*` mirrors the `paths` mapping in tsconfig.json so tests import the
 *   real app modules (`@/lib/crypto`, `@/lib/attacks`, …) unchanged.
 * - Default environment is `node` (Web Crypto is native in Node 18+); the
 *   sanitization suite opts into `jsdom` with a per-file docblock.
 * - `tests/setup.ts` guarantees `crypto.subtle` exists in every environment.
 */
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    setupFiles: ["tests/setup.ts"],
    globals: false,
    reporters: ["default"],
  },
});
