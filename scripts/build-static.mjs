/**
 * Build the static (GitHub Pages) bundle.
 *
 * Sets the switches the static build needs, clears stale output, parks the two
 * Node-only API routes out of `app/` for the duration of the build, runs
 * `next build`, then puts everything back:
 *
 *   STATIC_EXPORT=1             → `output: "export"` in next.config.mjs
 *   NEXT_PUBLIC_STATIC_EXPORT=1 → client code uses the localStorage relay
 *                                 (`lib/api/staticRelay.ts`) instead of `/api/*`
 *   NEXT_PUBLIC_BASE_PATH       → e.g. `/Crypto_Shield` for a project site
 *                                 (the workflow passes the repo name)
 *
 * Why the API routes move: `output: "export"` refuses route handlers that
 * need a server (`export const dynamic = "force-dynamic"`), so a Pages build
 * cannot contain `app/api/**` at all. They are restored in a `finally`, on
 * Ctrl+C, and on uncaught errors — the normal `npm run build` is untouched.
 *
 * Spawning through Node (rather than `STATIC_EXPORT=1 next build` in the npm
 * script) keeps the command working on Windows shells too.
 */

import { spawnSync } from "node:child_process";
import { rm, rename } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const apiSource = path.join(root, "app", "api");
const apiParked = path.join(root, ".static-build-parked-api");

/** Put the parked API routes back where they belong. */
async function restoreApiRoutes() {
  try {
    await rename(apiParked, apiSource);
    console.log("[build-static] restored app/api");
  } catch (cause) {
    if (cause?.code !== "ENOENT") {
      console.warn(`[build-static] could not restore app/api: ${cause?.message}`);
    }
  }
}

// Restore even if the build is interrupted.
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    void restoreApiRoutes().finally(() => process.exit(1));
  });
}
process.on("uncaughtException", (error) => {
  console.error(error);
  void restoreApiRoutes().finally(() => process.exit(1));
});

let parked = false;
try {
  // Start clean: a previous server build in `.next` would keep stale routes.
  for (const dir of [".next", "out"]) {
    await rm(path.join(root, dir), {
      recursive: true,
      force: true,
      maxRetries: 3,
      retryDelay: 100,
    });
  }

  await rm(apiParked, { recursive: true, force: true });
  try {
    await rename(apiSource, apiParked);
    parked = true;
    console.log("[build-static] parked app/api (static export has no server routes)");
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause; // no app/api → nothing to park
  }

  const env = {
    ...process.env,
    STATIC_EXPORT: "1",
    NEXT_PUBLIC_STATIC_EXPORT: "1",
    NEXT_TELEMETRY_DISABLED: "1",
  };

  console.log(
    `[build-static] next build (static)${
      env.NEXT_PUBLIC_BASE_PATH ? ` basePath=${env.NEXT_PUBLIC_BASE_PATH}` : ""
    }`,
  );

  const result = spawnSync("npx", ["next", "build"], { stdio: "inherit", env, shell: true });
  process.exitCode = result.status ?? 1;
} finally {
  if (parked) await restoreApiRoutes();
}
