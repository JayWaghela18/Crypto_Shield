/**
 * Security audit log tests — incident classification and JSON/CSV report
 * serialization. Pure functions, so these run in the default node environment.
 */

import { describe, expect, it } from "vitest";

import { classifySanitization, classifyVerification } from "@/lib/audit/classify";
import {
  buildIncidentReport,
  countBySeverity,
  incidentsToCsv,
} from "@/lib/audit/report";
import type { SecurityIncident, VerificationResult } from "@/lib/types";

const EMAIL = {
  id: "msg-1",
  sender: "admin@bank.com",
  recipient: "alice@cryptoshield.dev",
  subject: "URGENT: verify your account",
};

function incident(overrides: Partial<SecurityIncident> = {}): SecurityIncident {
  return {
    id: "inc-1",
    timestamp: 1_700_000_000_000,
    category: "spoofing",
    severity: "critical",
    title: "Spoofed sender blocked",
    detail: "Key binding failed",
    ...overrides,
  };
}

describe("incident classification", () => {
  it("classifies a failed key binding as critical spoofing", () => {
    const verification: VerificationResult = {
      status: "spoofed-unverified",
      reason: "Key binding FAILED",
      fingerprint: "AAAA",
      expectedFingerprint: "BBBB",
    };
    const result = classifyVerification(verification, EMAIL);
    expect(result?.category).toBe("spoofing");
    expect(result?.severity).toBe("critical");
    expect(result?.meta?.registeredFingerprint).toBe("BBBB");
  });

  it("classifies a failed GCM tag as MITM tampering", () => {
    const verification: VerificationResult = {
      status: "spoofed-tampered",
      reason: "Tampering Detected",
    };
    expect(classifyVerification(verification, EMAIL, "decrypt")?.category).toBe(
      "tampering",
    );
  });

  it("classifies a forged signature as spoofing", () => {
    const verification: VerificationResult = {
      status: "spoofed-tampered",
      reason: "Digital signature INVALID",
    };
    expect(classifyVerification(verification, EMAIL)?.category).toBe("spoofing");
  });

  it("classifies a revoked certificate", () => {
    const verification: VerificationResult = {
      status: "revoked",
      reason: "Certificate REVOKED",
      revoked: true,
    };
    const result = classifyVerification(verification, EMAIL);
    expect(result?.category).toBe("revoked-certificate");
    expect(result?.severity).toBe("high");
  });

  it("reports nothing for benign verdicts", () => {
    expect(
      classifyVerification({ status: "verified", reason: "ok" }, EMAIL),
    ).toBeNull();
    expect(
      classifyVerification({ status: "plaintext", reason: "no crypto" }, EMAIL),
    ).toBeNull();
  });

  it("classifies sanitization only when characters were stripped", () => {
    expect(classifySanitization("<p>hi</p>", "<p>hi</p>", EMAIL)).toBeNull();
    const result = classifySanitization(
      '<p>hi</p><img src=x onerror=alert(1)>',
      "<p>hi</p>",
      EMAIL,
    );
    expect(result?.category).toBe("sanitization");
    expect(result?.severity).toBe("medium");
    expect(result?.meta?.strippedChars).toBeGreaterThan(0);
  });
});

describe("incident report serialization", () => {
  it("counts severities in a stable order", () => {
    const counts = countBySeverity([
      incident({ id: "a", severity: "critical" }),
      incident({ id: "b", severity: "info" }),
      incident({ id: "c", severity: "critical" }),
    ]);
    expect(counts).toEqual({ critical: 2, info: 1 });
  });

  it("builds a JSON report with metadata", () => {
    const report = buildIncidentReport([incident()], "json");
    expect(report.filename).toMatch(/\.json$/);
    expect(report.mime).toBe("application/json");

    const parsed = JSON.parse(report.content);
    expect(parsed.total).toBe(1);
    expect(parsed.incidents).toHaveLength(1);
    expect(parsed.severityCounts.critical).toBe(1);
  });

  it("builds a CSV report with a header row", () => {
    const report = buildIncidentReport([incident()], "csv");
    expect(report.filename).toMatch(/\.csv$/);
    expect(report.mime).toContain("text/csv");

    const [header, row] = report.content.split("\r\n");
    expect(header).toContain("category");
    expect(header).toContain("severity");
    expect(row).toContain("spoofing");
  });

  it("escapes commas and quotes in CSV fields", () => {
    const csv = incidentsToCsv([
      incident({ detail: 'He said "stop", then left' }),
    ]);
    const row = csv.split("\r\n")[1];
    expect(row).toContain('"He said ""stop"", then left"');
  });

  it("produces a header-only CSV when there are no incidents", () => {
    const csv = incidentsToCsv([]);
    expect(csv.split("\r\n")).toHaveLength(1);
  });
});
