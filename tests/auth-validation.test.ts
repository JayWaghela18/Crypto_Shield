/**
 * Authentication boundary tests: request validation, redirect safety,
 * CSRF-style origin checks, rate limiting and bcrypt password handling.
 */

import { describe, expect, it } from "vitest";
import {
  hashPassword,
  verifyAgainstTimingEqualizer,
  verifyPassword,
} from "@/lib/auth/password";
import { consumeRateLimit } from "@/lib/auth/rateLimit";
import { isSameOriginRequest } from "@/lib/http/sameOrigin";
import { safeRelativePath } from "@/lib/http/redirect";
import {
  loginSchema,
  registerSchema,
  toFieldErrors,
} from "@/lib/validation/auth";

describe("registration schema", () => {
  it("normalizes name and email", () => {
    const parsed = registerSchema.parse({
      name: "  Ada Lovelace  ",
      email: "  Ada@Example.COM ",
      password: "correct horse battery",
    });
    expect(parsed.name).toBe("Ada Lovelace");
    expect(parsed.email).toBe("ada@example.com");
  });

  it("rejects a malformed email", () => {
    const result = registerSchema.safeParse({
      name: "Ada",
      email: "not-an-email",
      password: "correct horse battery",
    });
    expect(result.success).toBe(false);
    if (!result.success) expect(toFieldErrors(result.error).email).toMatch(/valid email/i);
  });

  it("rejects short passwords and one-character names", () => {
    const result = registerSchema.safeParse({
      name: "A",
      email: "a@example.com",
      password: "short",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const errors = toFieldErrors(result.error);
      expect(errors.name).toMatch(/at least 2/);
      expect(errors.password).toMatch(/at least 12/);
    }
  });

  it("rejects passwords beyond bcrypt's 72-byte limit", () => {
    const result = registerSchema.safeParse({
      name: "Ada",
      email: "ada@example.com",
      password: "🔐".repeat(30), // 120 bytes
    });
    expect(result.success).toBe(false);
    if (!result.success) expect(toFieldErrors(result.error).password).toMatch(/72 bytes/);
  });
});

describe("login schema", () => {
  it("normalizes the email but keeps the password verbatim", () => {
    const parsed = loginSchema.parse({
      email: "  USER@Example.com ",
      password: "  spaces matter  ",
    });
    expect(parsed.email).toBe("user@example.com");
    expect(parsed.password).toBe("  spaces matter  ");
  });

  it("rejects an empty password", () => {
    expect(loginSchema.safeParse({ email: "a@example.com", password: "" }).success).toBe(
      false,
    );
  });
});

describe("bcrypt password handling", () => {
  it("hashes with cost 12 and verifies the original password only", async () => {
    const hash = await hashPassword("correct horse battery");
    expect(hash).toMatch(/^\$2[aby]\$12\$/);
    expect(hash).not.toContain("correct horse battery");
    await expect(verifyPassword("correct horse battery", hash)).resolves.toBe(true);
    await expect(verifyPassword("Correct horse battery", hash)).resolves.toBe(false);
  }, 20_000);

  it("fails closed for an over-long password", async () => {
    await expect(hashPassword("x".repeat(73))).rejects.toThrow(/72-byte/);
    const hash = await hashPassword("correct horse battery");
    await expect(verifyPassword("x".repeat(73), hash)).resolves.toBe(false);
  }, 20_000);

  it("returns false for the timing equalizer", async () => {
    await expect(verifyAgainstTimingEqualizer("anything")).resolves.toBe(false);
  }, 20_000);
});

describe("same-origin guard", () => {
  const origin = "http://localhost:3000";
  const request = (method: string, headers: Record<string, string> = {}) =>
    new Request(`${origin}/api/auth/register`, { method, headers });

  it("accepts a same-origin POST", () => {
    expect(isSameOriginRequest(request("POST", { origin }))).toBe(true);
  });

  it("rejects a cross-origin POST", () => {
    expect(
      isSameOriginRequest(request("POST", { origin: "https://evil.example" })),
    ).toBe(false);
  });

  it("rejects a mutation with no Origin header", () => {
    expect(isSameOriginRequest(request("POST"))).toBe(false);
  });

  it("allows safe methods without an Origin header", () => {
    expect(isSameOriginRequest(request("GET"))).toBe(true);
  });
});

describe("rate limiting", () => {
  it("allows the configured burst then blocks with a retry delay", () => {
    const key = `test:${crypto.randomUUID()}`;
    expect(consumeRateLimit(key, 2, 60_000).allowed).toBe(true);
    expect(consumeRateLimit(key, 2, 60_000).allowed).toBe(true);
    const blocked = consumeRateLimit(key, 2, 60_000);
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);
  });
});

describe("redirect safety", () => {
  it("keeps same-site paths", () => {
    expect(safeRelativePath("/lab?tab=keys")).toBe("/lab?tab=keys");
  });

  it("rejects absolute, protocol-relative and backslash targets", () => {
    expect(safeRelativePath("https://evil.example")).toBe("/");
    expect(safeRelativePath("//evil.example")).toBe("/");
    expect(safeRelativePath("/\\evil.example")).toBe("/");
    expect(safeRelativePath(null)).toBe("/");
  });
});
