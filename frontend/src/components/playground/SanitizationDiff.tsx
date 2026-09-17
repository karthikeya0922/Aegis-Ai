"use client";

import type { SafeDetection } from "@/lib/hooks/useAegisStream";
import { EmptyState } from "@/components/ui/States";

/**
 * Original prompt (left) vs. what the provider actually received (right).
 *
 * Both strings arrive already redacted — the left pane by `makeSafe` in
 * `useAegisStream`, the right by `toInspectorPayload` on the server. This
 * component does no redaction of its own; it must never be the thing standing
 * between a secret and the screen.
 */

function Pane({ label, text, tone }: { label: string; text: string | null; tone?: "sanitized" }) {
  return (
    <div className="flex min-w-0 flex-col gap-10 p-14" style={{ background: "var(--aegis-bg-inspector)" }}>
      <span className="font-mono text-2xs tracking-logo text-aegis-text-40">{label}</span>
      {text ? (
        <pre
          className="m-0 overflow-x-auto whitespace-pre-wrap break-words font-mono text-sm-plus leading-mono"
          style={{ color: tone === "sanitized" ? "var(--aegis-text-85)" : "var(--aegis-text-75)" }}
        >
          {text}
        </pre>
      ) : (
        <span className="font-mono text-sm-plus text-aegis-text-35">—</span>
      )}
    </div>
  );
}

export function SanitizationDiff({
  original,
  sanitized,
  detections,
  hadSecrets,
}: {
  original: string;
  sanitized: string | null;
  detections: SafeDetection[];
  hadSecrets: boolean;
}) {
  if (!original) {
    return <EmptyState title="Nothing scanned yet" hint="The original and sanitized prompts appear side by side here." icon="◫" />;
  }

  return (
    <div className="flex flex-col gap-11">
      <div
        className="grid overflow-hidden rounded-md"
        style={{ gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 1, background: "var(--aegis-border)" }}
      >
        <Pane label="ORIGINAL" text={original} />
        <Pane
          label="SENT TO PROVIDER"
          tone="sanitized"
          text={sanitized ?? (detections.length === 0 ? original : null)}
        />
      </div>

      {hadSecrets && (
        <p
          className="m-0 rounded-sm px-11 py-8 text-sm-plus"
          style={{ border: "1px solid var(--status-block)", background: "rgba(239,68,68,0.08)", color: "var(--aegis-text-85)" }}
        >
          Secrets detected and stripped before this page rendered. The raw values were never sent to the browser.
        </p>
      )}

      {detections.length > 0 && (
        <div className="flex flex-wrap gap-6">
          {detections.map((d, i) => (
            <span
              key={`${d.category}-${i}`}
              className="flex items-center gap-6 rounded-full px-10 py-4 font-mono text-xs"
              style={{
                border: `1px solid ${d.secret ? "var(--status-block)" : "var(--status-warn)"}`,
                color: d.secret ? "var(--status-block)" : "var(--status-warn)",
              }}
              title={d.secret ? "Secret — raw value withheld" : d.preview}
            >
              {d.category}
              {d.placeholder && <span className="text-aegis-text-45">→ {d.placeholder}</span>}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
