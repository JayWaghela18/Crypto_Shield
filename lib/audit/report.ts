/**
 * Security Incident Report serialization.
 *
 * Pure functions (no React, no DOM) so the report format can be unit tested.
 * `buildIncidentReport` produces a downloadable file descriptor for either
 * JSON (structured, machine-readable) or CSV (spreadsheet-friendly).
 */

import type {
  IncidentReportFormat,
  IncidentSeverity,
  SecurityIncident,
} from "@/lib/types";

export interface IncidentReport {
  filename: string;
  mime: string;
  content: string;
}

/** Deterministic severity ordering for summaries. */
const SEVERITY_ORDER: IncidentSeverity[] = ["critical", "high", "medium", "info"];

/** Count incidents per severity (omitting zero counts). */
export function countBySeverity(
  incidents: SecurityIncident[],
): Partial<Record<IncidentSeverity, number>> {
  const counts: Partial<Record<IncidentSeverity, number>> = {};
  for (const severity of SEVERITY_ORDER) {
    const count = incidents.filter((i) => i.severity === severity).length;
    if (count > 0) counts[severity] = count;
  }
  return counts;
}

/** RFC 4180-style CSV field escaping. */
function csvField(value: string | number | undefined | null): string {
  if (value === undefined || value === null) return "";
  const text = String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

const CSV_COLUMNS = [
  "id",
  "timestamp",
  "isoTime",
  "category",
  "severity",
  "title",
  "sender",
  "recipient",
  "subject",
  "messageId",
  "verdict",
  "detail",
  "meta",
] as const;

/** Serialize incidents to CSV (header + one row per incident). */
export function incidentsToCsv(incidents: SecurityIncident[]): string {
  const rows = incidents.map((incident) =>
    [
      incident.id,
      incident.timestamp,
      new Date(incident.timestamp).toISOString(),
      incident.category,
      incident.severity,
      incident.title,
      incident.sender,
      incident.recipient,
      incident.subject,
      incident.messageId,
      incident.verdict,
      incident.detail,
      incident.meta ? JSON.stringify(incident.meta) : "",
    ]
      .map((field) => csvField(field as string | number | undefined))
      .join(","),
  );
  return [CSV_COLUMNS.join(","), ...rows].join("\r\n");
}

/** Timestamp suffix safe for filenames. */
function timestampSuffix(): string {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

/** Build the downloadable report for the requested format. */
export function buildIncidentReport(
  incidents: SecurityIncident[],
  format: IncidentReportFormat,
): IncidentReport {
  const suffix = timestampSuffix();

  if (format === "csv") {
    return {
      filename: `cryptoshield-incident-report-${suffix}.csv`,
      mime: "text/csv;charset=utf-8",
      content: incidentsToCsv(incidents),
    };
  }

  return {
    filename: `cryptoshield-incident-report-${suffix}.json`,
    mime: "application/json",
    content: JSON.stringify(
      {
        report: "CryptoShield Security Incident Report",
        version: 1,
        generated: new Date().toISOString(),
        total: incidents.length,
        severityCounts: countBySeverity(incidents),
        incidents,
      },
      null,
      2,
    ),
  };
}
