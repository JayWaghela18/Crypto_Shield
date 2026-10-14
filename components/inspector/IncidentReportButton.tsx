"use client";

/**
 * "Download Security Incident Report" — serializes the audit log to a local
 * JSON or CSV file. The dropdown keeps both formats one click away without
 * cluttering the inspector header.
 */

import { useState } from "react";
import { Download, FileJson, FileSpreadsheet } from "lucide-react";
import type { IncidentReportFormat } from "@/lib/types";
import { useAudit } from "@/store/AuditContext";
import { downloadFile } from "@/lib/download";

const FORMATS: {
  id: IncidentReportFormat;
  label: string;
  icon: typeof FileJson;
  hint: string;
}[] = [
  { id: "json", label: "JSON report", icon: FileJson, hint: "structured, machine-readable" },
  { id: "csv", label: "CSV report", icon: FileSpreadsheet, hint: "spreadsheet-friendly" },
];

export default function IncidentReportButton() {
  const { incidents, buildReport, clearIncidents } = useAudit();
  const [open, setOpen] = useState(false);

  function handleDownload(format: IncidentReportFormat) {
    downloadFile(buildReport(format));
    setOpen(false);
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        title="Download a structured JSON/CSV log of detected attacks"
        className="flex items-center gap-1.5 rounded-md border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 transition-colors hover:bg-slate-800 hover:text-slate-100"
      >
        <Download className="h-3.5 w-3.5" />
        Report
        <span
          className={[
            "rounded px-1 text-[10px] font-bold",
            incidents.length > 0
              ? "bg-red-500/20 text-red-300"
              : "bg-slate-700/60 text-slate-400",
          ].join(" ")}
        >
          {incidents.length}
        </span>
      </button>

      {open && (
        <>
          {/* Click-away backdrop */}
          <button
            aria-label="Close report menu"
            className="fixed inset-0 z-10 cursor-default"
            onClick={() => setOpen(false)}
          />
          <div className="absolute right-0 z-20 mt-1 w-52 overflow-hidden rounded-md border border-slate-700 bg-slate-900 shadow-xl">
            <p className="border-b border-slate-800 px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-500">
              Download incident report
            </p>
            {FORMATS.map(({ id, label, icon: Icon, hint }) => (
              <button
                key={id}
                onClick={() => handleDownload(id)}
                className="flex w-full items-start gap-2 px-3 py-2 text-left transition-colors hover:bg-slate-800"
              >
                <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                <span>
                  <span className="block text-xs font-semibold text-slate-200">{label}</span>
                  <span className="block text-[10px] text-slate-500">{hint}</span>
                </span>
              </button>
            ))}
            {incidents.length > 0 && (
              <button
                onClick={() => {
                  clearIncidents();
                  setOpen(false);
                }}
                className="w-full border-t border-slate-800 px-3 py-2 text-left text-[11px] text-slate-400 transition-colors hover:bg-slate-800 hover:text-red-300"
              >
                Clear log ({incidents.length})
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}
