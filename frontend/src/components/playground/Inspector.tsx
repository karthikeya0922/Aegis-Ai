"use client";

import type { Stage } from "@/lib/hooks/useAegisStream";
import { EmptyState } from "@/components/ui/States";

/**
 * The stage timeline.
 *
 * Rules that matter:
 *  - `duration_ms` is printed exactly as reported. A stage with none shows "—".
 *  - The blocking stage goes red; every stage after it is greyed out, because
 *    once the gate fails closed nothing downstream actually ran.
 *  - Cards reveal 80ms apart so the pipeline reads as a sequence, not a dump.
 */

const STAGE_LABELS: Record<string, string> = {
  pii_secret_scan: "PII & secret scan",
  prompt_injection_check: "Prompt injection check",
  sanitize: "Sanitization",
  policy_check: "Policy evaluation",
  cache_lookup: "Semantic cache",
  route: "Model routing",
  provider_call: "Provider call",
  grounding_check: "Grounding check",
  rehydrate: "Re-hydration",
};

function label(stage: string): string {
  return STAGE_LABELS[stage] ?? stage.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
}

const STATUS_STYLE: Record<Stage["status"], { color: string; glyph: string; text: string }> = {
  pass: { color: "var(--status-clean)", glyph: "✓", text: "pass" },
  flagged: { color: "var(--status-warn)", glyph: "!", text: "flagged" },
  blocked: { color: "var(--status-block)", glyph: "✕", text: "blocked" },
  skipped: { color: "var(--status-idle)", glyph: "–", text: "skipped" },
};

export function Inspector({
  stages,
  blockedAt,
  isLoading,
}: {
  stages: Stage[];
  blockedAt: number | null;
  isLoading: boolean;
}) {
  if (stages.length === 0) {
    return isLoading ? (
      <div className="flex flex-col gap-8">
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="animate-pulse rounded-sm"
            style={{ height: 46, background: "var(--aegis-surface-inset)", border: "1px solid var(--aegis-border-subtle)", animationDelay: `${i * 120}ms` }}
          />
        ))}
      </div>
    ) : (
      <EmptyState title="No pipeline run yet" hint="Send a prompt to watch each guardrail report in." icon="◌" />
    );
  }

  return (
    <ol className="m-0 flex list-none flex-col gap-8 p-0">
      {stages.map((s, i) => {
        // Downstream of a block, nothing executed — show it, but greyed.
        const downstream = blockedAt !== null && i > blockedAt;
        const style = STATUS_STYLE[s.status] ?? STATUS_STYLE.skipped;
        const color = downstream ? "var(--status-idle)" : style.color;

        return (
          <li
            key={`${s.stage}-${i}`}
            className="animate-stage-in flex items-center justify-between gap-10 rounded-sm px-11 py-8"
            style={{
              border: `1px solid ${s.status === "blocked" && !downstream ? "var(--status-block)" : "var(--aegis-border-subtle)"}`,
              background: s.status === "blocked" && !downstream ? "rgba(239,68,68,0.08)" : "var(--aegis-surface-inset)",
              opacity: downstream ? 0.38 : 1,
              animationDelay: `${i * 80}ms`, // --stage-stagger
            }}
          >
            <span className="flex min-w-0 items-center gap-8">
              <span
                className="flex shrink-0 items-center justify-center rounded-circle text-xs font-semibold"
                style={{ width: 18, height: 18, border: `1px solid ${color}`, color }}
              >
                {downstream ? "–" : style.glyph}
              </span>
              <span className="truncate text-sm-plus text-aegis-text-75">{label(s.stage)}</span>
            </span>

            <span className="flex shrink-0 items-center gap-10">
              <span className="font-mono text-xs uppercase tracking-caps-tight" style={{ color }}>
                {downstream ? "not run" : style.text}
              </span>
              <span className="min-w-[52px] text-right font-mono text-xs-plus" style={{ color: "var(--aegis-text-70)" }}>
                {downstream || s.duration_ms === null ? (
                  <span className="text-aegis-text-40">—</span>
                ) : (
                  `${s.duration_ms} ms`
                )}
              </span>
            </span>
          </li>
        );
      })}
    </ol>
  );
}
