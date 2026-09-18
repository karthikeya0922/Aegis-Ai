"use client";

import { Fragment, useMemo, useState } from "react";
import useSWR from "swr";
import type { AuditLogEntry } from "@aegis/types/aegis";
import { ruleColor, ruleLabel } from "@/lib/chart-theme";
import { EmptyState, ErrorState, Skeleton } from "@/components/ui/States";

/**
 * Paginated audit log.
 *
 * Reads `/api/audit/events` — the Next route handler proxy. The browser never
 * talks to the Python service directly, so the engine's URL and credential stay
 * server-side.
 */

const fetcher = async (url: string) => {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(res.status === 503 ? "Engine unavailable" : `Request failed (${res.status})`);
  return res.json();
};

interface Page {
  entries: AuditLogEntry[];
  total: number;
  page: number;
  pageSize: number;
  pageCount: number;
}

const ACTION_COLOR: Record<string, string> = {
  allow: "var(--status-clean)",
  warn: "var(--status-warn)",
  sanitize: "var(--status-sanitize)",
  block: "var(--status-block)",
};

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-4">
      <span className="text-xs uppercase tracking-caps-tight text-aegis-text-45">{label}</span>
      {children}
    </label>
  );
}

const inputStyle = {
  border: "1px solid var(--aegis-border)",
  background: "var(--aegis-surface-input)",
} as const;

export function AuditTable() {
  const [page, setPage] = useState(1);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [action, setAction] = useState("");
  const [provider, setProvider] = useState("");
  const [cacheHit, setCacheHit] = useState("");
  const [hasDetections, setHasDetections] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const query = useMemo(() => {
    const p = new URLSearchParams({ page: String(page), pageSize: "25" });
    if (from) p.set("from", new Date(from).toISOString());
    if (to) p.set("to", new Date(to).toISOString());
    if (action) p.set("action", action);
    if (provider) p.set("provider", provider);
    if (cacheHit) p.set("cacheHit", cacheHit);
    if (hasDetections) p.set("hasDetections", hasDetections);
    return p.toString();
  }, [page, from, to, action, provider, cacheHit, hasDetections]);

  const { data, error, isLoading, mutate } = useSWR<Page>(`/api/audit/events?${query}`, fetcher, {
    keepPreviousData: true,
    revalidateOnFocus: false,
  });

  function resetPage<T>(setter: (v: T) => void) {
    return (v: T) => {
      setter(v);
      setPage(1);
    };
  }

  return (
    <div className="flex flex-col gap-14">
      {/* filters */}
      <div className="grid gap-10" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))" }}>
        <Field label="From">
          <input type="date" value={from} onChange={(e) => resetPage(setFrom)(e.target.value)}
            className="rounded-sm px-10 py-7 font-mono text-sm-plus text-aegis-text outline-none" style={inputStyle} />
        </Field>
        <Field label="To">
          <input type="date" value={to} onChange={(e) => resetPage(setTo)(e.target.value)}
            className="rounded-sm px-10 py-7 font-mono text-sm-plus text-aegis-text outline-none" style={inputStyle} />
        </Field>
        <Field label="Policy action">
          <select value={action} onChange={(e) => resetPage(setAction)(e.target.value)}
            className="cursor-pointer rounded-sm px-10 py-7 text-sm-plus text-aegis-text outline-none" style={inputStyle}>
            <option value="">Any</option>
            <option value="allow">Allow</option>
            <option value="warn">Warn</option>
            <option value="sanitize">Sanitize</option>
            <option value="block">Block</option>
          </select>
        </Field>
        <Field label="Provider">
          <input value={provider} onChange={(e) => resetPage(setProvider)(e.target.value)} placeholder="any"
            className="rounded-sm px-10 py-7 font-mono text-sm-plus text-aegis-text outline-none" style={inputStyle} />
        </Field>
        <Field label="Cache">
          <select value={cacheHit} onChange={(e) => resetPage(setCacheHit)(e.target.value)}
            className="cursor-pointer rounded-sm px-10 py-7 text-sm-plus text-aegis-text outline-none" style={inputStyle}>
            <option value="">Any</option>
            <option value="true">Hit</option>
            <option value="false">Miss</option>
          </select>
        </Field>
        <Field label="Detections">
          <select value={hasDetections} onChange={(e) => resetPage(setHasDetections)(e.target.value)}
            className="cursor-pointer rounded-sm px-10 py-7 text-sm-plus text-aegis-text outline-none" style={inputStyle}>
            <option value="">Any</option>
            <option value="true">Has detections</option>
            <option value="false">None</option>
          </select>
        </Field>
      </div>

      {error ? (
        <ErrorState message={(error as Error).message} onRetry={() => void mutate()} />
      ) : isLoading && !data ? (
        <Skeleton height={280} />
      ) : !data || data.entries.length === 0 ? (
        <EmptyState title="No audit events match" hint="Widen the date range or clear the filters." icon="◫" />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-base">
              <thead>
                <tr className="text-left text-xs-plus uppercase tracking-caps text-aegis-text-40">
                  {["Time", "Request", "Action", "Provider", "Latency", "Entities", "Cache", "Cost"].map((h) => (
                    <th key={h} className="px-8 pb-10 font-normal" style={{ borderBottom: "1px solid var(--aegis-border-subtle)" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.entries.map((e, i) => {
                  const open = expanded === e.id;
                  return (
                    // Keyed Fragment: the row and its expanded detail are two
                    // siblings per entry, so the key has to sit on the wrapper.
                    <Fragment key={e.id}>
                      <tr
                        onClick={() => setExpanded(open ? null : e.id)}
                        className="animate-stage-in cursor-pointer transition-colors hover:bg-aegis-surface-inset"
                        style={{ borderBottom: "1px solid var(--aegis-border-faint)", animationDelay: `${Math.min(i, 12) * 30}ms` }}
                      >
                        <td className="px-8 py-11 font-mono text-sm-plus text-aegis-text-60">
                          {new Date(e.timestamp).toLocaleString()}
                        </td>
                        <td className="px-8 py-11 font-mono text-sm-plus text-aegis-text-70">{e.request_id}</td>
                        <td className="px-8 py-11">
                          <span className="rounded-full px-10 py-3 font-mono text-xs uppercase"
                            style={{ border: `1px solid ${ACTION_COLOR[e.action] ?? "var(--status-idle)"}`, color: ACTION_COLOR[e.action] ?? "var(--status-idle)" }}>
                            {e.action}
                          </span>
                        </td>
                        <td className="px-8 py-11 font-mono text-sm-plus">
                          {e.provider_used ?? <span className="text-aegis-text-40">—</span>}
                          {e.failover_used && <span className="ml-6 text-xs" style={{ color: "var(--status-warn)" }}>failover</span>}
                        </td>
                        <td className="px-8 py-11 font-mono text-sm-plus">
                          {e.latency_ms === null ? <span className="text-aegis-text-40">—</span> : `${e.latency_ms} ms`}
                        </td>
                        <td className="px-8 py-11 font-mono text-sm-plus">{e.scrubbed_entity_count}</td>
                        <td className="px-8 py-11 font-mono text-sm-plus" style={{ color: e.cache_hit ? "var(--status-cost)" : "var(--aegis-text-40)" }}>
                          {e.cache_hit ? "hit" : "miss"}
                        </td>
                        <td className="px-8 py-11 font-mono text-sm-plus">
                          {e.estimated_cost_usd === null ? <span className="text-aegis-text-40">—</span> : `$${e.estimated_cost_usd.toFixed(4)}`}
                        </td>
                      </tr>
                      {open && (
                        <tr>
                          <td colSpan={8} className="px-8 pb-14" style={{ background: "var(--aegis-surface-inset)" }}>
                            <RowDetail entry={e} />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-11">
            <span className="font-mono text-sm-plus text-aegis-text-45">
              Page {data.page} of {data.pageCount} · {data.total.toLocaleString()} events
            </span>
            <div className="flex gap-8">
              <PageButton disabled={data.page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Previous</PageButton>
              <PageButton disabled={data.page >= data.pageCount} onClick={() => setPage((p) => p + 1)}>Next</PageButton>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function PageButton({ children, disabled, onClick }: { children: React.ReactNode; disabled: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="cursor-pointer rounded-full px-13 py-7 font-sans text-base text-aegis-text-85 transition-colors hover:text-aegis-text disabled:cursor-not-allowed disabled:opacity-35"
      style={{ border: "1px solid var(--aegis-border-strong)", background: "transparent" }}
    >
      {children}
    </button>
  );
}

/** Row expand: that request's stage timeline plus its rule triggers. */
function RowDetail({ entry }: { entry: AuditLogEntry }) {
  return (
    <div className="flex flex-col gap-11 pt-11">
      <div className="flex flex-wrap gap-6">
        {entry.rule_triggers.length === 0 ? (
          <span className="font-mono text-sm-plus text-aegis-text-40">No rules triggered</span>
        ) : (
          entry.rule_triggers.map((r, i) => (
            <span key={`${r}-${i}`} className="rounded-full px-10 py-3 font-mono text-xs"
              style={{ border: `1px solid ${ruleColor(r)}`, color: ruleColor(r) }}>
              {ruleLabel(r)}
            </span>
          ))
        )}
      </div>

      <div className="grid gap-11" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))" }}>
        <Detail label="Model" value={entry.model_used} />
        <Detail label="Tokens" value={entry.tokens_consumed?.toLocaleString() ?? null} />
        <Detail label="Grounding" value={entry.grounding_status} />
        <Detail label="Grounding score" value={entry.grounding_score?.toFixed(2) ?? null} />
        <Detail label="Saved" value={entry.estimated_savings_usd === null ? null : `$${entry.estimated_savings_usd.toFixed(4)}`} />
        <Detail label="Carbon" value={entry.estimated_carbon_g === null ? null : `${entry.estimated_carbon_g.toFixed(2)} g`} />
      </div>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs uppercase tracking-caps-tight text-aegis-text-45">{label}</span>
      <span className="font-mono text-base-plus">{value ?? <span className="text-aegis-text-40">—</span>}</span>
    </div>
  );
}
