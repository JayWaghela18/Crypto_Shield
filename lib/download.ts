/**
 * Client-side file download helpers (browser only).
 *
 * Used by the Key Management UI and the Security Incident Report export.
 * Renders a transient object URL and clicks a synthetic anchor; nothing is
 * persisted and no network request is made.
 */

export interface DownloadableFile {
  filename: string;
  mime: string;
  content: string;
}

/** Trigger a download of one text file. No-op during SSR. */
export function downloadText(filename: string, mime: string, content: string): void {
  if (typeof window === "undefined") return;
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Revoke on the next tick so the click has been processed.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** Trigger a download for each file in order. */
export function downloadFiles(files: DownloadableFile[]): void {
  for (const file of files) downloadText(file.filename, file.mime, file.content);
}

/** Download a single DownloadableFile object. */
export function downloadFile(file: DownloadableFile): void {
  downloadText(file.filename, file.mime, file.content);
}
