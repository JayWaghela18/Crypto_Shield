"use client";

/**
 * Security audit log — collects detected incidents (spoofing, MITM tampering,
 * XSS sanitization, revoked certificates, key-import attempts) so the inspector
 * can export a structured JSON/CSV report.
 *
 * Recording is deliberately centralised here: components only describe WHAT
 * happened, and the report serialization lives in `lib/audit/report.ts`.
 */

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type {
  IncidentReportFormat,
  SecurityIncident,
  SecurityIncidentInput,
} from "@/lib/types";
import { buildIncidentReport, type IncidentReport } from "@/lib/audit/report";

/** Keep the log bounded so a long session stays responsive. */
const MAX_INCIDENTS = 500;

interface AuditContextValue {
  incidents: SecurityIncident[];
  /** Append a detected incident (id + timestamp are assigned here). */
  recordIncident: (input: SecurityIncidentInput) => void;
  /** Empty the audit log. */
  clearIncidents: () => void;
  /** Serialize the current log into a downloadable report. */
  buildReport: (format: IncidentReportFormat) => IncidentReport;
}

const AuditContext = createContext<AuditContextValue | null>(null);

export function AuditProvider({ children }: { children: ReactNode }) {
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);

  const recordIncident = useCallback((input: SecurityIncidentInput) => {
    setIncidents((prev) =>
      [...prev, { ...input, id: crypto.randomUUID(), timestamp: Date.now() }].slice(
        -MAX_INCIDENTS,
      ),
    );
  }, []);

  const clearIncidents = useCallback(() => setIncidents([]), []);

  const buildReport = useCallback(
    (format: IncidentReportFormat) => buildIncidentReport(incidents, format),
    [incidents],
  );

  const value = useMemo<AuditContextValue>(
    () => ({ incidents, recordIncident, clearIncidents, buildReport }),
    [incidents, recordIncident, clearIncidents, buildReport],
  );

  return <AuditContext.Provider value={value}>{children}</AuditContext.Provider>;
}

/** Access the security audit log. Throws outside the provider. */
export function useAudit(): AuditContextValue {
  const ctx = useContext(AuditContext);
  if (!ctx) throw new Error("useAudit must be used within AuditProvider");
  return ctx;
}
