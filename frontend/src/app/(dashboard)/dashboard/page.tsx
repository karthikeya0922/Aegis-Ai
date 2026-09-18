"use client";

import { CacheHitChart, CostSavedChart, LatencyChart, ProviderUsageChart, RequestVolumeChart, ThreatTypeChart } from "@/components/dashboard/Charts";
import { KpiRow } from "@/components/dashboard/KpiRow";
import { RangePicker } from "@/components/dashboard/RangePicker";
import { ThreatsTable } from "@/components/dashboard/ThreatsTable";
import { ExportButton } from "@/components/audit/ExportButton";
import { Panel, PanelHeader } from "@/components/ui/Panel";
import { PanelState } from "@/components/ui/States";
import { useDashboard } from "@/lib/dashboard-context";

export default function OverviewPage() {
  const { metrics, isLoading, error, refresh, range } = useDashboard();
  const series = metrics?.series ?? [];
  const loading = isLoading && !metrics;

  const rangeLabel =
    range === "1h" ? "Last hour" : range === "24h" ? "Last 24 hours" : range === "7d" ? "Last 7 days" : "Last 30 days";

  const wrap = (isEmpty: boolean, empty: { title: string; hint?: string }, node: React.ReactNode) => (
    <PanelState isLoading={loading} error={error} isEmpty={isEmpty} empty={empty} onRetry={refresh} height={210}>
      {node}
    </PanelState>
  );

  return (
    <div className="flex flex-col gap-14">
      <div className="flex flex-wrap items-center justify-between gap-14">
        <h1 className="m-0 text-5xl font-bold tracking-tight">Gateway Overview</h1>
        <div className="flex flex-wrap items-center gap-11">
          <RangePicker />
          <ExportButton />
        </div>
      </div>

      <div className="grid gap-14" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", alignItems: "start" }}>
        <Panel span glow="rgba(255,138,0,0.28)">
          <PanelHeader
            title="Today's Activity"
            subtitle={`${rangeLabel} · ${metrics ? metrics.total.toLocaleString() : "—"} requests governed`}
          />
          <KpiRow />
        </Panel>

        <Panel glow="rgba(1,117,255,0.3)">
          <PanelHeader title="Request Volume" subtitle="Requests over time" />
          {wrap(series.length === 0, { title: "No requests in this window" }, <RequestVolumeChart data={series} />)}
        </Panel>

        <Panel glow="rgba(239,68,68,0.28)">
          <PanelHeader title="Threat Events by Type" subtitle="PII, secrets and injection attempts" />
          {wrap(series.length === 0, { title: "No threats detected" }, <ThreatTypeChart data={series} />)}
        </Panel>

        <Panel glow="rgba(34,197,94,0.25)">
          <PanelHeader title="Provider Usage" subtitle="Share of traffic, with failover overlay" />
          {wrap(
            (metrics?.providers.length ?? 0) === 0,
            { title: "No provider calls yet" },
            <ProviderUsageChart providers={metrics?.providers ?? []} failoverRate={metrics?.kpis.failoverRate ?? null} />,
          )}
        </Panel>

        <Panel glow="rgba(255,138,0,0.3)">
          <PanelHeader title="Cache Hit Rate" subtitle="Semantic cache effectiveness" />
          {wrap(series.length === 0, { title: "No cache activity" }, <CacheHitChart data={series} />)}
        </Panel>

        <Panel glow="rgba(255,138,0,0.3)">
          <PanelHeader title="Cost Avoided" subtitle="Cumulative spend saved by cache and routing" />
          {wrap(series.length === 0, { title: "No savings recorded" }, <CostSavedChart data={series} />)}
        </Panel>

        <Panel glow="rgba(123,63,242,0.28)">
          <PanelHeader title="Latency" subtitle="p50 / p95 / p99 across all providers" />
          {wrap(
            !metrics || (metrics.latency.p50 === null && metrics.latency.p95 === null && metrics.latency.p99 === null),
            { title: "No latency samples" },
            <LatencyChart latency={metrics?.latency ?? { p50: null, p95: null, p99: null }} />,
          )}
        </Panel>

        <Panel span glow="rgba(239,68,68,0.25)">
          <PanelHeader title="Top Threats Blocked" subtitle="What the guardrails caught" />
          {wrap((metrics?.threats.length ?? 0) === 0, { title: "Nothing caught yet" }, <ThreatsTable threats={metrics?.threats ?? []} />)}
        </Panel>
      </div>
    </div>
  );
}
