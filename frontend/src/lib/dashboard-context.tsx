"use client";

import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import useSWR from "swr";

/**
 * The dashboard's ONE polling source.
 *
 * Every panel reads from this context. No component fetches `/api/metrics` on its
 * own — a second poller would double the load on the engine and let two panels
 * disagree about what "now" is.
 */

export type RangeKey = "1h" | "24h" | "7d" | "30d";

export interface Bucket {
  t: string;
  ts: string;
  allowed: number;
  sanitized: number;
  blocked: number;
  total: number;
  pii: number;
  secrets: number;
  injection: number;
  cacheHits: number;
  savedUsd: number;
  cumulativeSavedUsd: number;
}

export interface MetricsPayload {
  range: RangeKey;
  from: string;
  to: string;
  generated_at: string;
  total: number;
  series: Bucket[];
  kpis: {
    requests: number;
    savedUsd: number | null;
    spendUsd: number | null;
    threatsBlocked: number;
    entitiesScrubbed: number;
    cacheHitRate: number | null;
    failoverRate: number | null;
    medianLatencyMs: number | null;
  };
  latency: { p50: number | null; p95: number | null; p99: number | null };
  providers: Array<{ name: string; value: number }>;
  threats: Array<{ rule: string; count: number }>;
}

interface DashboardValue {
  range: RangeKey;
  setRange: (r: RangeKey) => void;
  metrics: MetricsPayload | undefined;
  isLoading: boolean;
  error: Error | undefined;
  refresh: () => void;
  health: { status: "ok" | "degraded" | "down" | "unknown"; label: string };
}

const DashboardContext = createContext<DashboardValue | null>(null);

const fetcher = async (url: string) => {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) {
    const err = new Error(res.status === 503 ? "Engine unavailable" : `Request failed (${res.status})`);
    throw err;
  }
  return res.json();
};

export function DashboardProvider({ children }: { children: ReactNode }) {
  const [range, setRange] = useState<RangeKey>("24h");

  const { data, error, isLoading, mutate } = useSWR<MetricsPayload>(
    `/api/metrics?range=${range}`,
    fetcher,
    {
      refreshInterval: 5_000,
      revalidateOnFocus: false,
      keepPreviousData: true,
      shouldRetryOnError: true,
      errorRetryInterval: 10_000,
    },
  );

  const value = useMemo<DashboardValue>(() => {
    const health: DashboardValue["health"] =
      error ? { status: "down", label: "Engine unreachable" }
      : isLoading && !data ? { status: "unknown", label: "Connecting…" }
      : { status: "ok", label: "Engine OK" };

    return {
      range,
      setRange,
      metrics: data,
      isLoading,
      error: error as Error | undefined,
      refresh: () => void mutate(),
      health,
    };
  }, [range, data, error, isLoading, mutate]);

  return <DashboardContext.Provider value={value}>{children}</DashboardContext.Provider>;
}

export function useDashboard(): DashboardValue {
  const ctx = useContext(DashboardContext);
  if (!ctx) throw new Error("useDashboard must be used inside <DashboardProvider>");
  return ctx;
}
