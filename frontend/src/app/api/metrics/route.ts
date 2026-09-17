import { NextRequest, NextResponse } from "next/server";
import type { AuditLogEntry } from "@aegis/types/aegis";
import { engineFetch, ENGINE_UNAVAILABLE } from "@/lib/server/engine";

export const dynamic = "force-dynamic";

/**
 * GET /api/metrics?range=24h
 *
 * The dashboard's single polling source. Aggregates the engine's audit trail into
 * the series every panel reads, so there is one query per poll rather than one per
 * chart. Never returns invented numbers: a bucket with no data is reported as such
 * and the UI renders an empty state.
 */

const RANGES = { "1h": 3_600_000, "24h": 86_400_000, "7d": 604_800_000, "30d": 2_592_000_000 } as const;
type RangeKey = keyof typeof RANGES;

const BUCKETS: Record<RangeKey, { count: number; label: (d: Date) => string }> = {
  "1h": { count: 12, label: (d) => `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}` },
  "24h": { count: 24, label: (d) => `${String(d.getHours()).padStart(2, "0")}:00` },
  "7d": { count: 7, label: (d) => d.toLocaleDateString(undefined, { weekday: "short" }) },
  "30d": { count: 30, label: (d) => `${d.getMonth() + 1}/${d.getDate()}` },
};

function pct(values: number[], p: number): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return Math.round(sorted[idx]);
}

const SECRET = (c: string) => c.startsWith("SECRET_");
const PII = (c: string) => c.startsWith("PII_");

export async function GET(req: NextRequest) {
  const rangeParam = req.nextUrl.searchParams.get("range") ?? "24h";
  const range: RangeKey = rangeParam in RANGES ? (rangeParam as RangeKey) : "24h";
  const windowMs = RANGES[range];
  const to = new Date();
  const from = new Date(to.getTime() - windowMs);

  let entries: AuditLogEntry[];
  try {
    const res = await engineFetch("/internal/audit/events", {
      method: "GET",
      query: { from: from.toISOString(), to: to.toISOString(), limit: "5000" },
    });
    if (!res.ok) return NextResponse.json(ENGINE_UNAVAILABLE, { status: 503 });
    const body = (await res.json()) as { entries?: AuditLogEntry[] };
    entries = Array.isArray(body.entries) ? body.entries : [];
  } catch {
    return NextResponse.json(ENGINE_UNAVAILABLE, { status: 503 });
  }

  const { count, label } = BUCKETS[range];
  const step = windowMs / count;
  const buckets = Array.from({ length: count }, (_, i) => {
    const start = from.getTime() + i * step;
    return {
      t: label(new Date(start)),
      ts: new Date(start).toISOString(),
      allowed: 0,
      sanitized: 0,
      blocked: 0,
      total: 0,
      pii: 0,
      secrets: 0,
      injection: 0,
      cacheHits: 0,
      savedUsd: 0,
      cumulativeSavedUsd: 0,
    };
  });

  const latencies: number[] = [];
  const providerCounts = new Map<string, number>();
  const threatCounts = new Map<string, number>();
  let cacheHits = 0;
  let savedTotal = 0;
  let costTotal = 0;
  let scrubbedTotal = 0;
  let failoverCount = 0;

  for (const e of entries) {
    const ts = Date.parse(e.timestamp);
    if (!Number.isFinite(ts)) continue;
    const idx = Math.min(count - 1, Math.max(0, Math.floor((ts - from.getTime()) / step)));
    const b = buckets[idx];

    b.total += 1;
    if (e.action === "block") b.blocked += 1;
    else if (e.action === "sanitize") b.sanitized += 1;
    else b.allowed += 1;

    for (const rule of e.rule_triggers ?? []) {
      threatCounts.set(rule, (threatCounts.get(rule) ?? 0) + 1);
      if (SECRET(rule)) b.secrets += 1;
      else if (PII(rule)) b.pii += 1;
      else if (rule === "PROMPT_INJECTION") b.injection += 1;
    }

    if (e.cache_hit) {
      b.cacheHits += 1;
      cacheHits += 1;
    }
    if (e.failover_used) failoverCount += 1;
    if (typeof e.latency_ms === "number") latencies.push(e.latency_ms);
    if (typeof e.estimated_savings_usd === "number") {
      b.savedUsd += e.estimated_savings_usd;
      savedTotal += e.estimated_savings_usd;
    }
    if (typeof e.estimated_cost_usd === "number") costTotal += e.estimated_cost_usd;
    scrubbedTotal += e.scrubbed_entity_count ?? 0;
    if (e.provider_used) providerCounts.set(e.provider_used, (providerCounts.get(e.provider_used) ?? 0) + 1);
  }

  let running = 0;
  for (const b of buckets) {
    running += b.savedUsd;
    b.cumulativeSavedUsd = Number(running.toFixed(4));
    b.savedUsd = Number(b.savedUsd.toFixed(4));
  }

  const total = entries.length;

  return NextResponse.json(
    {
      range,
      from: from.toISOString(),
      to: to.toISOString(),
      generated_at: to.toISOString(),
      total,
      series: buckets,
      kpis: {
        requests: total,
        // `null`, not 0 — "no data" and "zero" are different and the UI says so.
        savedUsd: total === 0 ? null : Number(savedTotal.toFixed(2)),
        spendUsd: total === 0 ? null : Number(costTotal.toFixed(2)),
        threatsBlocked: entries.filter((e) => e.action === "block").length,
        entitiesScrubbed: scrubbedTotal,
        cacheHitRate: total === 0 ? null : Number((cacheHits / total).toFixed(4)),
        failoverRate: total === 0 ? null : Number((failoverCount / total).toFixed(4)),
        medianLatencyMs: pct(latencies, 50),
      },
      latency: { p50: pct(latencies, 50), p95: pct(latencies, 95), p99: pct(latencies, 99) },
      providers: [...providerCounts.entries()]
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value),
      threats: [...threatCounts.entries()]
        .map(([rule, count]) => ({ rule, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8),
    },
    { headers: { "cache-control": "no-store" } },
  );
}
