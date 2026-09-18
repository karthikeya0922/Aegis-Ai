"use client";

import { useDashboard, type RangeKey } from "@/lib/dashboard-context";

const RANGES: RangeKey[] = ["1h", "24h", "7d", "30d"];

export function RangePicker() {
  const { range, setRange } = useDashboard();
  return (
    <div className="flex rounded-full p-1" style={{ border: "1px solid var(--aegis-border)" }}>
      {RANGES.map((r) => (
        <button
          key={r}
          onClick={() => setRange(r)}
          aria-pressed={range === r}
          className="cursor-pointer rounded-full border-0 px-13 py-6 font-sans text-base transition-colors duration-200"
          style={{
            background: range === r ? "var(--aegis-surface-toggle)" : "transparent",
            color: range === r ? "var(--aegis-text)" : "var(--aegis-text-45)",
          }}
        >
          {r}
        </button>
      ))}
    </div>
  );
}
