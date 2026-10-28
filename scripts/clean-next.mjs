/**
 * Remove the `.next` build directory before starting `next dev`.
 *
 * Why this exists: a stale production build (or a dev build interrupted by
 * OneDrive/Dropbox folder sync) leaves entries Next's own cleanup cannot
 * `readlink`, which makes `next dev` crash with
 * `EINVAL: invalid argument, readlink ...`. Deleting the folder ourselves,
 * ignoring per-entry failures, keeps `npm run dev` reliable everywhere.
 */
import { rm } from "node:fs/promises";
import path from "node:path";

const dir = path.join(process.cwd(), ".next");

try {
  await rm(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  console.log("[clean-next] removed .next");
} catch (error) {
  // A locked file is not fatal: Next will reuse what it can.
  console.warn(
    `[clean-next] could not fully remove .next: ${error instanceof Error ? error.message : error}`,
  );
}
