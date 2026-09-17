"use client";

import type { ReactNode } from "react";

/**
 * Empty / loading / error states.
 *
 * The design file has none — every panel in it assumes data. These keep the
 * "never render an invented number" rule honest: when there is nothing to show,
 * the panel says so rather than drawing a flat line through zero.
 */

export function EmptyState({ title, hint, icon = "○" }: { title: string; hint?: string; icon?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-8 px-14 py-22 text-center">
      <span
        className="flex items-center justify-center rounded-circle text-3xl text-aegis-text-35"
        style={{ width: 52, height: 52, border: "1px dashed var(--aegis-border-strong)" }}
      >
        {icon}
      </span>
      <span className="text-md text-aegis-text-60">{title}</span>
      {hint && <span className="max-w-hero text-sm-plus text-aegis-text-40">{hint}</span>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-10 px-14 py-22 text-center">
      <span
        className="flex items-center justify-center rounded-circle text-3xl"
        style={{ width: 52, height: 52, border: "1px solid var(--status-block)", color: "var(--status-block)" }}
      >
        !
      </span>
      <span className="text-md text-aegis-text-70">{message}</span>
      {onRetry && (
        <button
          onClick={onRetry}
          className="cursor-pointer rounded-full px-13 py-7 text-base text-aegis-text-85 transition-colors hover:text-aegis-text"
          style={{ border: "1px solid var(--aegis-border-strong)", background: "transparent" }}
        >
          Retry
        </button>
      )}
    </div>
  );
}

export function Skeleton({ height = 210 }: { height?: number }) {
  return (
    <div
      className="w-full animate-pulse rounded-lg"
      style={{ height, background: "var(--aegis-surface-inset)", border: "1px solid var(--aegis-border-subtle)" }}
    />
  );
}

/**
 * Wraps a panel body in the right state. `isEmpty` is computed by the caller
 * because "empty" differs per chart (no buckets vs. all-zero buckets).
 */
export function PanelState({
  isLoading,
  error,
  isEmpty,
  empty,
  onRetry,
  height,
  children,
}: {
  isLoading?: boolean;
  error?: Error;
  isEmpty?: boolean;
  empty: { title: string; hint?: string; icon?: string };
  onRetry?: () => void;
  height?: number;
  children: ReactNode;
}) {
  if (error) return <ErrorState message={error.message} onRetry={onRetry} />;
  if (isLoading) return <Skeleton height={height} />;
  if (isEmpty) return <EmptyState {...empty} />;
  return <>{children}</>;
}
