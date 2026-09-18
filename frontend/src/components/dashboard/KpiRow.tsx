"use client";

import { useDashboard } from "@/lib/dashboard-context";

/**
 * The four headline numbers. A `null` metric renders "—", never 0 — the engine
 * reporting nothing and the engine reporting zero are different facts.
 */

function fmt(value: number | null, render: (v: number) => string): string {
  return value === null ? "—" : render(value);
}

export function KpiRow() {
  const { metrics, isLoading } = useDashboard();
  const k = metrics?.kpis;

  const cards = [
    { icon: "$", orb: "var(--orb-cost)", value: fmt(k?.savedUsd ?? null, (v) => `$${v.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`), label: "Spend saved" },
    { icon: "◆", orb: "var(--orb-block)", value: fmt(k?.threatsBlocked ?? null, (v) => v.toLocaleString()), label: "Threats blocked" },
    { icon: "◇", orb: "var(--orb-sanitize)", value: fmt(k?.entitiesScrubbed ?? null, (v) => v.toLocaleString()), label: "Entities scrubbed" },
    { icon: "~", orb: "var(--orb-info)", value: fmt(k?.medianLatencyMs ?? null, (v) => `${v.toLocaleString()} ms`), label: "Median latency" },
  ];

  return (
    <div className="mt-15 grid gap-11" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))" }}>
      {cards.map((c, i) => (
        <div
          key={c.label}
          className="animate-stage-in rounded-lg p-13 transition-transform duration-300 ease-out-expo hover:-translate-y-1"
          style={{
            border: "1px solid var(--aegis-border-subtle)",
            background: "var(--aegis-surface-inset)",
            animationDelay: `${i * 80}ms`,
          }}
        >
          <span
            className="flex items-center justify-center rounded-md text-lg"
            style={{ width: 34, height: 34, background: c.orb }}
          >
            {c.icon}
          </span>
          <div className="mt-12 text-7xl font-bold tracking-tight" style={{ opacity: isLoading && !metrics ? 0.35 : 1 }}>
            {c.value}
          </div>
          <div className="mt-3 text-base-plus text-aegis-text-70">{c.label}</div>
        </div>
      ))}
    </div>
  );
}
