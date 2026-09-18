"use client";

import type { StreamState } from "@/lib/hooks/useAegisStream";
import { EmptyState, ErrorState } from "@/components/ui/States";

/**
 * The response pane: streamed text, real metadata, and a security footer whose
 * checks are driven by telemetry flags.
 *
 * A check that did not run renders grey "not run". It never renders a green tick
 * on the strength of an absent flag — silence is not a pass.
 */

type CheckState = "pass" | "warn" | "fail" | "not-run";

const CHECK_STYLE: Record<CheckState, { color: string; glyph: string; label: string }> = {
  pass: { color: "var(--status-clean)", glyph: "✓", label: "pass" },
  warn: { color: "var(--status-warn)", glyph: "!", label: "warn" },
  fail: { color: "var(--status-block)", glyph: "✕", label: "blocked" },
  "not-run": { color: "var(--status-idle)", glyph: "–", label: "not run" },
};

function Check({ name, state }: { name: string; state: CheckState }) {
  const s = CHECK_STYLE[state];
  return (
    <span className="flex items-center gap-6" style={{ opacity: state === "not-run" ? 0.55 : 1 }}>
      <span
        className="flex items-center justify-center rounded-circle text-2xs"
        style={{ width: 16, height: 16, border: `1px solid ${s.color}`, color: s.color }}
      >
        {s.glyph}
      </span>
      <span className="text-sm-plus text-aegis-text-65">{name}</span>
      <span className="font-mono text-2xs uppercase tracking-caps-tight" style={{ color: s.color }}>
        {s.label}
      </span>
    </span>
  );
}

function Meta({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs uppercase tracking-caps-tight text-aegis-text-45">{label}</span>
      <span className="font-mono text-base-plus">
        {value ?? <span className="text-aegis-text-40">—</span>}
      </span>
    </div>
  );
}

export function EgressPanel({ state, onRetry }: { state: StreamState; onRetry?: () => void }) {
  const { status, responseText, telemetry, grounding, detections, error } = state;

  if (status === "error") {
    return <ErrorState message={error ?? "The request failed."} onRetry={onRetry} />;
  }

  if (status === "blocked") {
    return (
      <div className="flex flex-col gap-11">
        <div
          className="flex flex-col items-center gap-8 rounded-md px-14 py-19 text-center"
          style={{ border: "1px solid var(--status-block)", background: "rgba(239,68,68,0.08)" }}
        >
          <span className="font-mono text-8xl font-bold" style={{ textShadow: "var(--shadow-403)" }}>403</span>
          <span className="font-mono text-xs tracking-mono-label text-aegis-text-70">REQUEST BLOCKED</span>
          <span className="max-w-hero text-md text-aegis-text-70">{error}</span>
        </div>
        <SecurityFooter state={state} />
      </div>
    );
  }

  if (status === "idle") {
    return <EmptyState title="No response yet" hint="The provider's reply streams in here once the guardrails pass." icon="◇" />;
  }

  // Grounding verdicts arrive after the stream; reflected in SecurityFooter.

  return (
    <div className="flex flex-col gap-14">
      <div className="min-h-[120px]">
        {responseText ? (
          <p className="m-0 whitespace-pre-wrap text-md leading-mono text-aegis-text-78">
            {responseText}
            {status === "streaming" && (
              <span className="ml-1 inline-block animate-pulse-dot" style={{ width: 7, height: 15, background: "var(--aegis-blue)", verticalAlign: "text-bottom" }} />
            )}
          </p>
        ) : status === "scanning" ? (
          <span className="font-mono text-sm-plus text-aegis-text-45">Scanning prompt…</span>
        ) : (
          <span className="font-mono text-sm-plus text-aegis-text-45">Waiting for the first token…</span>
        )}
      </div>

      <div
        className="grid gap-12 rounded-md p-13"
        style={{ gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", background: "var(--aegis-surface-inset)", border: "1px solid var(--aegis-border-subtle)" }}
      >
        <Meta label="Provider" value={telemetry?.provider_used ?? null} />
        <Meta label="Failover" value={telemetry?.failover_used === undefined ? null : telemetry.failover_used ? `yes → ${telemetry.provider_used ?? "?"}` : "no"} />
        <Meta label="Cache" value={telemetry?.cache_hit === undefined ? null : telemetry.cache_hit ? "hit" : "miss"} />
        <Meta label="Entities" value={detections.length > 0 ? String(detections.length) : telemetry ? "0" : null} />
        <Meta
          label="Grounding"
          value={
            grounding?.score !== undefined && grounding?.score !== null ? grounding.score.toFixed(2)
            : telemetry?.grounding_score !== undefined && telemetry?.grounding_score !== null ? telemetry.grounding_score.toFixed(2)
            : null
          }
        />
      </div>

      <SecurityFooter state={state} />
    </div>
  );
}

function SecurityFooter({ state }: { state: StreamState }) {
  const { stages, telemetry, grounding, detections, status } = state;
  const stageBy = (name: string) => stages.find((s) => s.stage.includes(name));

  const toState = (stageName: string): CheckState => {
    const s = stageBy(stageName);
    if (!s) return "not-run";
    if (s.status === "blocked") return "fail";
    if (s.status === "flagged") return "warn";
    if (s.status === "skipped") return "not-run";
    return "pass";
  };

  const sanitizeState: CheckState =
    stageBy("sanitize") ? toState("sanitize")
    : detections.length > 0 ? "warn"
    : status === "done" ? "pass"
    : "not-run";

  const groundingState: CheckState =
    grounding?.status === "block" ? "fail"
    : grounding?.status === "warn" ? "warn"
    : grounding?.status === "pass" ? "pass"
    : telemetry?.grounding_status === "unverified" ? "warn"
    : "not-run";

  return (
    <div
      className="flex flex-wrap gap-14 rounded-md px-13 py-11"
      style={{ borderTop: "1px solid var(--aegis-border-subtle)", background: "var(--aegis-surface-inset)" }}
    >
      <Check name="PII / secret scan" state={toState("pii")} />
      <Check name="Injection check" state={toState("injection")} />
      <Check name="Sanitization" state={sanitizeState} />
      <Check name="Grounding" state={groundingState} />
      <Check name="Re-hydration" state={grounding?.rehydrated === true ? "pass" : grounding ? "not-run" : "not-run"} />
    </div>
  );
}
