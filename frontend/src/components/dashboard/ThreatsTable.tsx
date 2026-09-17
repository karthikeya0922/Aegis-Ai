"use client";

import { ruleColor, ruleLabel } from "@/lib/chart-theme";
import { EmptyState } from "@/components/ui/States";

export function ThreatsTable({ threats }: { threats: Array<{ rule: string; count: number }> }) {
  if (threats.length === 0) {
    return <EmptyState title="Nothing caught yet" hint="Rules that fire will be ranked here by volume." icon="◇" />;
  }
  const max = Math.max(...threats.map((t) => t.count));

  return (
    <div className="flex flex-col">
      <div
        className="flex gap-11 pb-10 text-xs-plus uppercase tracking-caps text-aegis-text-40"
        style={{ borderBottom: "1px solid var(--aegis-border-subtle)" }}
      >
        <span style={{ flex: "0 0 26px" }}>#</span>
        <span className="flex-1">Rule</span>
        <span style={{ flex: "0 0 130px" }}>Share</span>
        <span className="text-right" style={{ flex: "0 0 58px" }}>Count</span>
      </div>
      {threats.map((t, i) => (
        <div
          key={t.rule}
          className="animate-stage-in flex items-center gap-11 py-12"
          style={{ borderBottom: "1px solid var(--aegis-border-faint)", animationDelay: `${i * 60}ms` }}
        >
          <span className="font-mono text-sm-plus text-aegis-text-40" style={{ flex: "0 0 26px" }}>
            {String(i + 1).padStart(2, "0")}
          </span>
          <span className="min-w-0 flex-1 truncate text-md">{ruleLabel(t.rule)}</span>
          <span
            className="overflow-hidden rounded-full"
            style={{ flex: "0 0 130px", height: 7, background: "var(--aegis-surface-track)" }}
          >
            <span
              className="block h-full rounded-full transition-[width] duration-700 ease-out-expo"
              style={{ width: `${Math.round((t.count / max) * 100)}%`, background: ruleColor(t.rule) }}
            />
          </span>
          <span className="text-right font-mono text-base" style={{ flex: "0 0 58px" }}>{t.count}</span>
        </div>
      ))}
    </div>
  );
}
