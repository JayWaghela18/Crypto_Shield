/**
 * Demo identities shared by the client and the API routes.
 *
 * A tiny fixed directory keeps attack demos easy to type: these addresses
 * always exist in the simulated PKI, so a fresh browser can address mail to
 * them before anyone has registered.
 */

/** Default account address (kept for tests and legacy demo drafts). */
export const CURRENT_USER = "alice@cryptoshield.dev";

/** Quick-switch profiles offered on the authentication screen. */
export const DEMO_PROFILES = [
  {
    id: "alice",
    email: "alice@cryptoshield.dev",
    name: "Alice Mercer",
    role: "Security Analyst",
    avatar: "🛰️",
    blurb: "Primary operator · sees the classic inbox",
  },
  {
    id: "bob",
    email: "bob@cryptoshield.dev",
    name: "Bob Ferreira",
    role: "Field Engineer",
    avatar: "🛠️",
    blurb: "Counterparty · receives Alice's mail",
  },
  {
    id: "bank",
    email: "admin@bank.com",
    name: "Bank Admin",
    role: "Financial Admin",
    avatar: "🏦",
    blurb: "High-value target · spoofing demos",
  },
] as const;

export type DemoProfileId = (typeof DEMO_PROFILES)[number]["id"];

/** Known demo users — offered as recipients in the compose form. */
export const DEMO_USERS = [
  ...DEMO_PROFILES.map((profile) => ({
    email: profile.email,
    displayName: profile.name,
    role: profile.role,
    avatar: profile.avatar,
  })),
  { email: "ceo@cryptoshield.dev", displayName: "CEO (target)", role: "Executive", avatar: "👔" },
  { email: "security@cryptoshield.dev", displayName: "Security Operations", role: "SOC", avatar: "🛡️" },
] as const;

/** Address used by the spoofing simulation (never held by this client). */
export const SPOOF_TARGET = "admin@bank.com";
