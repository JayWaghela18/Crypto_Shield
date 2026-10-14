/**
 * Demo identities shared by the client and the API routes.
 * Phase 1 ships a tiny fixed directory so spoofing demos are easy to type.
 */

/** The account this browser is currently "logged in" as. */
export const CURRENT_USER = "alice@cryptoshield.dev";

/** Known demo users — offered as recipients in the compose form. */
export const DEMO_USERS = [
  { email: "alice@cryptoshield.dev", displayName: "Alice (you)" },
  { email: "bob@cryptoshield.dev", displayName: "Bob" },
  { email: "ceo@cryptoshield.dev", displayName: "CEO (target)" },
  // Phase 3: a bank identity that PUBLISHES its key to the directory, so the
  // spoofing simulation can prove the attacker does not hold its private key
  // (signature key mismatch → Invalid Signature Warning).
  { email: "admin@bank.com", displayName: "Bank (published key)" },
] as const;

/** Address used by the spoofing simulation (never held by this client). */
export const SPOOF_TARGET = "admin@bank.com";
