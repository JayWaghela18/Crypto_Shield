/**
 * Password hashing — bcrypt with cost 12.
 *
 * bcrypt is deliberately slow and salts every hash, so a stolen database does
 * not yield reusable password material. bcrypt only considers the first 72
 * bytes of a password; registration rejects longer inputs rather than silently
 * truncating them.
 */

import bcrypt from "bcryptjs";
import {
  MAX_PASSWORD_BYTES,
  passwordByteLength,
} from "@/lib/auth/passwordPolicy";

export const BCRYPT_COST = 12;

/**
 * A real bcrypt hash of a server-side random value. Failed logins for unknown
 * accounts still run one comparison so response timing does not reveal whether
 * an email exists (account enumeration).
 */
const TIMING_EQUALIZER_HASH =
  "$2b$12$TJsM391DO0r43TRiE.IPbeY1Zs/ID1m9ziYkdbSsNh7P33YrruZHm";

/** Hash a plaintext password. Throws if the input exceeds bcrypt's 72-byte limit. */
export async function hashPassword(password: string): Promise<string> {
  if (passwordByteLength(password) > MAX_PASSWORD_BYTES) {
    throw new Error("Password exceeds bcrypt's 72-byte limit");
  }
  return bcrypt.hash(password, BCRYPT_COST);
}

/** Constant-time-ish verification. Malformed hashes fail closed. */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  if (passwordByteLength(password) > MAX_PASSWORD_BYTES) return false;
  try {
    return await bcrypt.compare(password, hash);
  } catch {
    return false;
  }
}

/** Burn a comparable amount of time when the account does not exist. */
export async function verifyAgainstTimingEqualizer(password: string): Promise<false> {
  try {
    await bcrypt.compare(password.slice(0, MAX_PASSWORD_BYTES), TIMING_EQUALIZER_HASH);
  } catch {
    // Ignore — the result is intentionally discarded.
  }
  return false;
}
