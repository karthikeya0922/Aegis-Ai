"use client";

import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart,
  Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { axisProps, gridProps, PROVIDER_COLORS, SERIES, STROKE_WIDTH, tooltipProps } from "@/lib/chart-theme";
import type { Bucket } from "@/lib/dashboard-context";
import { EmptyState } from "@/components/ui/States";

const H = 210; // --chart-h, same height as the design file's SVG

function hasAny(rows: Bucket[], keys: (keyof Bucket)[]): boolean {
  return rows.some((r) => keys.some((k) => Number(r[k]) > 0));
}

export function Legend({ items }: { items: Array<{ label: string; color: string }> }) {
  return (
    <div className="mt-14 flex flex-wrap gap-13 text-sm-plus text-aegis-text-65">
      {items.map((i) => (
        <span key={i.label} className="flex items-center gap-6">
          <span className="rounded-chip" style={{ width: 9, height: 9, background: i.color }} />
          {i.label}
        </span>
      ))}
    </div>
  );
}

/* ---------------------------------------------------------------- 1. volume */

export function RequestVolumeChart({ data }: { data: Bucket[] }) {
  if (!hasAny(data, ["total"])) {
    return <EmptyState title="No requests in this window" hint="Traffic through the gateway will appear here." icon="◠" />;
  }
  return (
    <>
      <ResponsiveContainer width="100%" height={H}>
        <AreaChart data={data} margin={{ top: 6, right: 4, left: -18, bottom: 0 }}>
          <defs>
            <linearGradient id="gVolume" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--status-info)" stopOpacity={0.45} />
              <stop offset="100%" stopColor="var(--status-info)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid {...gridProps} />
          <XAxis dataKey="t" {...axisProps} interval="preserveStartEnd" minTickGap={24} />
          <YAxis {...axisProps} width={44} allowDecimals={false} />
          <Tooltip {...tooltipProps} />
          <Area
            type="monotone" dataKey="total" name="Requests"
            stroke={SERIES.allowed} strokeWidth={STROKE_WIDTH} fill="url(#gVolume)"
            dot={false} activeDot={{ r: 4, strokeWidth: 0 }}
          />
        </AreaChart>
      </ResponsiveContainer>
      <Legend items={[{ label: "Requests", color: SERIES.allowed }]} />
    </>
  );
}

/* ------------------------------------------------------- 2. threats by type */

export function ThreatTypeChart({ data }: { data: Bucket[] }) {
  if (!hasAny(data, ["pii", "secrets", "injection"])) {
    return <EmptyState title="No threats detected" hint="PII, secrets and injection attempts are broken out here." icon="◇" />;
  }
  return (
    <>
      <ResponsiveContainer width="100%" height={H}>
        <BarChart data={data} margin={{ top: 6, right: 4, left: -18, bottom: 0 }} barCategoryGap="28%">
          <CartesianGrid {...gridProps} />
          <XAxis dataKey="t" {...axisProps} interval="preserveStartEnd" minTickGap={24} />
          <YAxis {...axisProps} width={44} allowDecimals={false} />
          <Tooltip {...tooltipProps} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
          <Bar dataKey="pii" name="PII" stackId="t" fill={SERIES.pii} />
          <Bar dataKey="secrets" name="Secrets" stackId="t" fill={SERIES.secrets} />
          <Bar dataKey="injection" name="Injection" stackId="t" fill={SERIES.injection} radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
      <Legend
        items={[
          { label: "PII", color: SERIES.pii },
          { label: "Secrets", color: SERIES.secrets },
          { label: "Injection", color: SERIES.injection },
        ]}
      />
    </>
  );
}

/* ------------------------------------------------- 3. provider usage donut */

export function ProviderUsageChart({
  providers,
  failoverRate,
}: {
  providers: Array<{ name: string; value: number }>;
  failoverRate: number | null;
}) {
  if (providers.length === 0) {
    return <EmptyState title="No provider calls yet" hint="Share of traffic per upstream provider appears here." icon="◐" />;
  }
  const total = providers.reduce((a, p) => a + p.value, 0);

  return (
    <div className="flex flex-wrap items-center gap-18">
      <div className="relative" style={{ width: 178, height: 178 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={providers} dataKey="value" nameKey="name"
              innerRadius={58} outerRadius={84} paddingAngle={2} stroke="none" startAngle={90} endAngle={-270}
            >
              {providers.map((p, i) => (
                <Cell key={p.name} fill={PROVIDER_COLORS[i % PROVIDER_COLORS.length]} />
              ))}
            </Pie>
            {/* failover overlay: an inner ring showing the share that needed a fallback */}
            {failoverRate !== null && failoverRate > 0 && (
              <Pie
                data={[
                  { name: "Failover", value: failoverRate },
                  { name: "Primary", value: Math.max(0, 1 - failoverRate) },
                ]}
                dataKey="value" innerRadius={44} outerRadius={52} stroke="none" startAngle={90} endAngle={-270}
              >
                <Cell fill="var(--status-warn)" />
                <Cell fill="var(--aegis-surface-track)" />
              </Pie>
            )}
            <Tooltip {...tooltipProps} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center gap-1">
          <span className="text-4xl font-bold">{total.toLocaleString()}</span>
          <span className="text-xs-plus text-aegis-text-45">calls</span>
        </div>
      </div>

      <div className="flex min-w-[160px] flex-col gap-8">
        {providers.map((p, i) => (
          <span key={p.name} className="flex items-center justify-between gap-11 text-base">
            <span className="flex items-center gap-7 text-aegis-text-70">
              <span className="rounded-chip" style={{ width: 9, height: 9, background: PROVIDER_COLORS[i % PROVIDER_COLORS.length] }} />
              {p.name}
            </span>
            <span className="font-mono text-sm-plus">{Math.round((p.value / total) * 100)}%</span>
          </span>
        ))}
        <span className="mt-4 flex items-center justify-between gap-11 border-t pt-8 text-base" style={{ borderColor: "var(--aegis-border-subtle)" }}>
          <span className="flex items-center gap-7 text-aegis-text-70">
            <span className="rounded-chip" style={{ width: 9, height: 9, background: "var(--status-warn)" }} />
            Failover
          </span>
          <span className="font-mono text-sm-plus">
            {failoverRate === null ? <span className="text-aegis-text-40">—</span> : `${(failoverRate * 100).toFixed(1)}%`}
          </span>
        </span>
      </div>
    </div>
  );
}

/* --------------------------------------------------- 4. cache hit rate line */

export function CacheHitChart({ data }: { data: Bucket[] }) {
  const rows = data.map((b) => ({ t: b.t, rate: b.total > 0 ? Number(((b.cacheHits / b.total) * 100).toFixed(1)) : null }));
  if (!rows.some((r) => r.rate !== null)) {
    return <EmptyState title="No cache activity" hint="Semantic-cache hit rate per bucket appears here." icon="◔" />;
  }
  return (
    <>
      <ResponsiveContainer width="100%" height={H}>
        <LineChart data={rows} margin={{ top: 6, right: 4, left: -18, bottom: 0 }}>
          <CartesianGrid {...gridProps} />
          <XAxis dataKey="t" {...axisProps} interval="preserveStartEnd" minTickGap={24} />
          <YAxis {...axisProps} width={44} domain={[0, 100]} unit="%" />
          <Tooltip {...tooltipProps} formatter={(v) => [`${Number(v)}%`, "Hit rate"]} />
          <Line
            type="monotone" dataKey="rate" name="Hit rate" connectNulls
            stroke={SERIES.cache} strokeWidth={STROKE_WIDTH} strokeLinecap="round"
            dot={false} activeDot={{ r: 4, strokeWidth: 0 }}
          />
        </LineChart>
      </ResponsiveContainer>
      <Legend items={[{ label: "Cache hit rate", color: SERIES.cache }]} />
    </>
  );
}

/* ----------------------------------------------- 5. cumulative cost avoided */

export function CostSavedChart({ data }: { data: Bucket[] }) {
  if (!hasAny(data, ["cumulativeSavedUsd"])) {
    return <EmptyState title="No savings recorded" hint="Spend avoided by cache hits and routing accumulates here." icon="◠" />;
  }
  return (
    <>
      <ResponsiveContainer width="100%" height={H}>
        <AreaChart data={data} margin={{ top: 6, right: 4, left: -10, bottom: 0 }}>
          <defs>
            <linearGradient id="gSaved" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--status-cost)" stopOpacity={0.5} />
              <stop offset="100%" stopColor="var(--status-cost)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid {...gridProps} />
          <XAxis dataKey="t" {...axisProps} interval="preserveStartEnd" minTickGap={24} />
          <YAxis {...axisProps} width={52} tickFormatter={(v: number) => `$${v}`} />
          <Tooltip {...tooltipProps} formatter={(v) => [`$${Number(v).toFixed(2)}`, "Saved"]} />
          <Area
            type="monotone" dataKey="cumulativeSavedUsd" name="Saved"
            stroke={SERIES.saved} strokeWidth={STROKE_WIDTH} fill="url(#gSaved)"
            dot={false} activeDot={{ r: 4, strokeWidth: 0 }}
          />
        </AreaChart>
      </ResponsiveContainer>
      <Legend items={[{ label: "Cumulative spend avoided", color: SERIES.saved }]} />
    </>
  );
}

/* ------------------------------------------------------------- 6. latency */

export function LatencyChart({ latency }: { latency: { p50: number | null; p95: number | null; p99: number | null } }) {
  const rows = [
    { name: "p50", ms: latency.p50, fill: SERIES.clean },
    { name: "p95", ms: latency.p95, fill: SERIES.warn },
    { name: "p99", ms: latency.p99, fill: SERIES.blocked },
  ];
  if (rows.every((r) => r.ms === null)) {
    return <EmptyState title="No latency samples" hint="Percentiles appear once requests complete." icon="◫" />;
  }
  return (
    <>
      <ResponsiveContainer width="100%" height={H}>
        <BarChart data={rows} margin={{ top: 6, right: 4, left: -8, bottom: 0 }} barCategoryGap="34%">
          <CartesianGrid {...gridProps} />
          <XAxis dataKey="name" {...axisProps} />
          <YAxis {...axisProps} width={52} tickFormatter={(v: number) => `${v}ms`} />
          <Tooltip {...tooltipProps} formatter={(v) => [`${Number(v)} ms`, "Latency"]} />
          <Bar dataKey="ms" name="Latency" radius={[6, 6, 0, 0]}>
            {rows.map((r) => <Cell key={r.name} fill={r.fill} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <Legend
        items={[
          { label: "p50", color: SERIES.clean },
          { label: "p95", color: SERIES.warn },
          { label: "p99", color: SERIES.blocked },
        ]}
      />
    </>
  );
}
