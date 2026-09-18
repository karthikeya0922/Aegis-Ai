"use client";

import { useState } from "react";
import { useDashboard } from "@/lib/dashboard-context";

/**
 * Streams the PDF audit report through our own proxy and saves it as
 * `aegis-audit-<from>-<to>.pdf`.
 */
export function ExportButton() {
  const { metrics, range } = useDashboard();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function download() {
    setBusy(true);
    setError(null);

    const to = metrics?.to ?? new Date().toISOString();
    const from = metrics?.from ?? new Date(Date.now() - 86_400_000).toISOString();

    try {
      const res = await fetch(`/api/audit/report?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
      if (!res.ok) throw new Error(res.status === 503 ? "Report service unavailable" : `Export failed (${res.status})`);

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aegis-audit-${from.slice(0, 10)}-${to.slice(0, 10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Export failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-4">
      <button
        onClick={download}
        disabled={busy}
        title={`Export the ${range} window as a PDF`}
        className="cursor-pointer rounded-full px-15 py-8 font-sans text-base text-aegis-text-85 transition-all duration-300 hover:text-aegis-text disabled:cursor-not-allowed disabled:opacity-40"
        style={{ border: "1px solid var(--aegis-border-strong)", background: "transparent" }}
      >
        {busy ? "Preparing…" : "Export Audit Report"}
      </button>
      {error && <span className="text-xs" style={{ color: "var(--status-block)" }}>{error}</span>}
    </div>
  );
}
