/**
 * Password policy constants shared by the browser form and the server.
 *
 * Deliberately free of bcrypt/Node imports: client components must be able to
 * validate input without pulling the hashing library into their module graph.
 */

export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_BYTES = 72;

export function passwordByteLength(password: string): number {
  return new TextEncoder().encode(password).byteLength;
}
