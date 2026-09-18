"""`aegis status`: one screen of what the deployment is doing, read from the
Inspector's existing APIs. Every estimate is printed with its basis; the
fairness gap that is not closed is printed, not hidden."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegis_cli.config import CLIConfig


@dataclass
class Snapshot:
    health: dict[str, Any] | None = None
    gateway_ok: bool | None = None
    metrics: dict[str, Any] | None = None
    security: dict[str, Any] | None = None
    sustainability: dict[str, Any] | None = None
    providers: dict[str, Any] | None = None
    reviews: dict[str, Any] | None = None
    fairness: dict[str, Any] | None = None
    errors: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in ("health", "gateway_ok", "metrics", "security", "sustainability",
                                              "providers", "reviews", "fairness", "errors")}


def collect(cfg: CLIConfig, *, hours: int = 24, client: httpx.Client | None = None,
            gateway_client: httpx.Client | None = None) -> Snapshot:
    snap = Snapshot()
    own = client is None
    client = client or httpx.Client(base_url=cfg.engine_url, timeout=8.0)
    calls = {
        "health": ("/api/health", {}),
        "metrics": ("/api/metrics", {"window_hours": hours}),
        "security": ("/api/metrics/security", {"window_hours": hours}),
        "sustainability": ("/api/metrics/sustainability", {"window_hours": hours}),
        "providers": ("/api/metrics/providers", {"window_hours": hours}),
        "reviews": ("/api/reviews", {"status": "PENDING"}),
        "fairness": ("/api/fairness/report", {}),
    }
    try:
        for key, (path, params) in calls.items():
            try:
                r = client.get(path, params=params)
                if r.status_code == 200:
                    setattr(snap, key, r.json())
                else:
                    snap.errors[key] = f"HTTP {r.status_code}"
            except httpx.HTTPError as exc:
                snap.errors[key] = exc.__class__.__name__
    finally:
        if own:
            client.close()
    gw_own = gateway_client is None
    gateway_client = gateway_client or httpx.Client(base_url=cfg.gateway_url, timeout=4.0)
    try:
        r = gateway_client.get("/api/metrics", params={"range": "24h"})
        snap.gateway_ok = r.status_code == 200
    except httpx.HTTPError:
        snap.gateway_ok = False
    finally:
        if gw_own:
            gateway_client.close()
    return snap


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _kv(title: str, rows: list[tuple[str, Any]]) -> Table:
    t = Table(title=title, title_justify="left", title_style="bold", show_header=False, box=None, pad_edge=False)
    t.add_column(style="dim", min_width=26); t.add_column()
    for k, v in rows:
        t.add_row(k, "-" if v is None else str(v))
    return t


def _pct(x: float | None) -> str:
    return "-" if x is None else f"{x * 100:.1f}%"


def render(snap: Snapshot, cfg: CLIConfig, console: Console) -> None:
    h = snap.health
    if h:
        not_ok = [c for c in h.get("components", []) if c.get("status") != "ok"]
        head = f"inspector [bold]{h.get('status')}[/bold]  {h.get('phase')}  up {h.get('uptime_seconds', 0):.0f}s  ({cfg.engine_url})"
        lines = [head]
        for c in not_ok:
            lines.append(f"  [yellow]{c['name']}[/yellow]: {c.get('detail')}")
    else:
        lines = [f"inspector [red]unreachable[/red] ({cfg.engine_url}): {snap.errors.get('health', '?')}"]
    lines.append(f"gateway   {'[green]ok[/green]' if snap.gateway_ok else '[red]unreachable[/red]'}  ({cfg.gateway_url})")
    console.print(Panel("\n".join(lines), title="services", title_align="left"))

    if not snap.metrics:
        console.print(f"[dim]metrics unavailable: {snap.errors.get('metrics', '?')}[/dim]")
        return

    m, s, su, p = snap.metrics, snap.security or {}, snap.sustainability or {}, snap.providers or {}
    lat = m.get("latency", {})
    cost = m.get("cost", {})
    tables = [
        _kv(f"traffic (last {m.get('window_hours')}h)", [
            ("requests", m.get("total_requests")),
            ("blocked / sanitised", f"{m.get('blocked_requests')} / {m.get('sanitized_requests')}"),
            ("latency p50 / p95", f"{lat.get('p50_ms')} / {lat.get('p95_ms')} ms"),
            ("inspector overhead p50", f"{lat.get('inspector_overhead_p50_ms')} ms"),
            ("tokens", m.get("tokens", {}).get("total_tokens")),
        ]),
        _kv("security", [
            ("PII detections", s.get("pii_detections")),
            ("secret detections", s.get("secret_detections")),
            ("credential blocks", s.get("credential_blocks")),
            ("injection blocks", s.get("injection_blocks")),
            ("egress flags", s.get("egress_flags")),
            ("top rules", ", ".join(f"{r['rule_id']}x{r['count']}" for r in s.get("top_rules", [])[:4]) or "-"),
        ]),
        _kv("cache and sustainability (estimates)", [
            ("cache hit rate", f"{_pct(su.get('cache_hit_rate'))}  ({su.get('cache_hits')} hits / {su.get('cache_misses')} misses)"),
            ("estimated spend", f"${cost.get('estimated_spend_usd')}"),
            ("estimated saved", f"${cost.get('estimated_saved_usd')}"),
            ("estimated energy", f"{su.get('estimated_energy_wh')} Wh  ({su.get('estimated_co2_g')} g CO2)"),
            ("avoided by cache", f"{su.get('estimated_energy_avoided_wh')} Wh  ({su.get('estimated_co2_avoided_g')} g CO2)"),
        ]),
    ]
    for t in tables:
        console.print(t)
    console.print(f"[dim]cost basis: {cost.get('basis', '-')}[/dim]")
    console.print(f"[dim]energy basis: {su.get('basis', '-')}[/dim]")

    pt = Table(title="providers", title_justify="left", title_style="bold", box=None, pad_edge=False)
    for col in ("provider", "requests", "failures", "failover in/out", "last seen"):
        pt.add_column(col)
    for row in p.get("providers", []):
        pt.add_row(row.get("provider", "?"), str(row.get("requests")), str(row.get("failures")),
                   f"{row.get('failover_in')}/{row.get('failover_out')}", str(row.get("last_seen", "-"))[:19])
    if not p.get("providers"):
        pt.add_row("-", "-", "-", "-", "-")
    console.print(pt)
    console.print(f"[dim]failover events: {p.get('failover_events', 0)}[/dim]")

    rv = snap.reviews or {}
    console.print(f"[bold]reviews[/bold]  pending: {rv.get('total', 0)}"
                  + ("  -> aegis reviews list" if rv.get("total") else ""))

    f = snap.fairness or {}
    cur = f.get("current")
    if cur:
        groups = ", ".join(f"{g.get('group')} {g.get('recall'):.3f}" for g in cur.get("groups", []))
        gap = cur.get("recall_gap")
        console.print(f"[bold]fairness (PERSON recall)[/bold]  {groups}")
        gap_line = f"  worst-best gap [bold]{gap:.3f}[/bold]" if gap is not None else "  gap: -"
        if f.get("gap_closed") is not None:
            gap_line += f"   gap_closed {f.get('gap_closed')}"
        console.print(gap_line)
    else:
        console.print("[bold]fairness[/bold]  no run recorded (POST /api/fairness/run)")
    console.print(f"[dim]{(f.get('disclaimer') or '')[:160]}[/dim]")
