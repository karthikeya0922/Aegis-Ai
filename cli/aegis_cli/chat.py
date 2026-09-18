"""`aegis chat`: a guarded conversation through the Aegis Gateway.

The CLI never calls a provider itself. It sends to the Gateway's
`/api/v1/chat/completions` with `stream: true`, so routing, failover, the
semantic cache and the audit row all happen exactly as they do for any other
client -- and then renders the `aegis.*` SSE frames the Gateway emits as the
terminal Inspector: pipeline stages with measured timings, the sanitised
prompt, the streamed answer, and a footer with the provider, cache and
estimate lines.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aegis_cli.config import CLIConfig, load_session_id

_STAGE_MARK = {"pass": ("[green]ok[/green]", ""), "flagged": ("[yellow]!![/yellow]", "yellow"),
               "blocked": ("[red]XX[/red]", "red"), "skipped": ("[dim]--[/dim]", "dim")}


# ---------------------------------------------------------------------------
# SSE
# ---------------------------------------------------------------------------


@dataclass
class SSEEvent:
    event: str
    data: str


def iter_sse(lines: Iterator[str]) -> Iterator[SSEEvent]:
    """Minimal text/event-stream parser: `event:` + one or more `data:` lines,
    dispatched on a blank line."""
    event = "message"
    data: list[str] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if line == "":
            if data:
                yield SSEEvent(event, "\n".join(data))
            event, data = "message", []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip())
    if data:
        yield SSEEvent(event, "\n".join(data))


# ---------------------------------------------------------------------------
# Outcome
# ---------------------------------------------------------------------------


@dataclass
class ChatOutcome:
    request_id: str | None = None
    action: str | None = None
    error_code: str | None = None
    blocked: bool = False
    http_status: int = 0
    scan: dict[str, Any] | None = None
    grounding: dict[str, Any] | None = None
    telemetry: dict[str, Any] | None = None
    answer: str = ""
    streamed: str = ""
    error_message: str | None = None
    audit: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        if self.error_message and not self.blocked:
            return 2
        return 1 if self.blocked else 0


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


def chat(
    prompt: str,
    *,
    cfg: CLIConfig,
    mode: str = "sanitize",
    no_cache: bool = False,
    confidential: bool = False,
    reference_docs: list[str] | None = None,
    model: str | None = None,
    history: list[dict[str, str]] | None = None,
    on_token: Callable[[str], None] | None = None,
    on_scan: Callable[[dict[str, Any]], None] | None = None,
    client: httpx.Client | None = None,
    timeout: float = 120.0,
) -> ChatOutcome:
    out = ChatOutcome()
    headers = {
        "content-type": "application/json",
        "accept": "text/event-stream",
        "x-session-id": load_session_id(),
        "x-aegis-mode": "strict" if mode == "strict" else "sanitize",
    }
    if no_cache:
        headers["x-aegis-no-cache"] = "true"
    if confidential:
        headers["x-aegis-confidential"] = "true"
    if reference_docs:
        headers["x-aegis-reference-docs"] = json.dumps(reference_docs)
    body = {"model": model or "aegis-routed", "stream": True,
            "messages": [*(history or []), {"role": "user", "content": prompt}]}

    own = client is None
    client = client or httpx.Client(base_url=cfg.gateway_url, timeout=timeout)
    try:
        with client.stream("POST", "/api/v1/chat/completions", headers=headers, json=body) as r:
            out.http_status = r.status_code
            ctype = r.headers.get("content-type", "")
            if "text/event-stream" not in ctype:
                raw = r.read().decode("utf-8", errors="replace")
                try:
                    payload = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    payload = {"error": {"message": raw[:500]}}
                errobj = payload.get("error") or {}
                out.error_code = errobj.get("code")
                out.error_message = errobj.get("message") or f"HTTP {r.status_code}"
                out.request_id = errobj.get("request_id") or payload.get("request_id")
                out.blocked = r.status_code in (400, 403) and bool(out.error_code)
                out.action = "block" if out.blocked else None
                return out
            for ev in iter_sse(r.iter_lines()):
                if ev.data == "[DONE]":
                    break
                try:
                    d = json.loads(ev.data)
                except json.JSONDecodeError:
                    continue
                if ev.event == "aegis.scan":
                    out.scan = d
                    out.action = d.get("action")
                    out.error_code = d.get("error_code")
                    if on_scan:
                        on_scan(d)
                elif ev.event == "aegis.grounding":
                    out.grounding = d
                    out.request_id = out.request_id or d.get("request_id")
                elif ev.event == "aegis.telemetry":
                    out.telemetry = d
                    out.request_id = out.request_id or d.get("request_id")
                    if d.get("error") and not out.answer:
                        out.error_message = d["error"]
                elif ev.event == "message":
                    for ch in d.get("choices", []):
                        delta = (ch.get("delta") or {}).get("content")
                        if delta:
                            out.answer += delta
                            if on_token:
                                on_token(delta)
                else:
                    out.extra[ev.event] = d
    except httpx.HTTPError as exc:
        out.error_message = f"gateway unreachable at {cfg.gateway_url}: {exc.__class__.__name__}"
    finally:
        if own:
            client.close()
    # Streamed tokens cannot be retracted. The trailing aegis.grounding frame
    # carries what the client should finally show: the rehydrated text, or the
    # Gateway's fallback on a grounding block.
    out.streamed = out.answer
    g = out.grounding or {}
    if g.get("final_text") and (g.get("blocked") or g.get("rehydrated")):
        out.answer = g["final_text"]
    return out


def fetch_audit(request_id: str, *, cfg: CLIConfig, client: httpx.Client | None = None) -> dict[str, Any] | None:
    own = client is None
    client = client or httpx.Client(base_url=cfg.engine_url, timeout=10.0)
    try:
        r = client.get(f"/api/requests/{request_id}")
        return r.json() if r.status_code == 200 else None
    except httpx.HTTPError:
        return None
    finally:
        if own:
            client.close()


def create_appeal(request_id: str, justification: str, *, cfg: CLIConfig, decision: str = "BLOCK",
                  client: httpx.Client | None = None) -> tuple[int, dict[str, Any]]:
    own = client is None
    client = client or httpx.Client(base_url=cfg.engine_url, timeout=10.0)
    try:
        r = client.post("/api/reviews", json={
            "request_id": request_id, "tenant_id": cfg.tenant_id, "original_decision": decision,
            "user_justification": justification,
        })
        return r.status_code, (r.json() if r.content else {})
    finally:
        if own:
            client.close()


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_stages(stages: list[dict[str, Any]], console: Console, title: str = "pipeline") -> None:
    t = Table(show_header=False, box=None, pad_edge=False, title=title, title_justify="left", title_style="bold")
    t.add_column(width=2); t.add_column(min_width=22); t.add_column(justify="right", width=10); t.add_column(style="dim")
    for s in stages:
        mark, style = _STAGE_MARK.get(s.get("status", "skipped"), ("?", ""))
        name = s.get("name") or s.get("stage") or "?"
        dur = s.get("duration_ms")
        durs = f"{dur:.1f} ms" if isinstance(dur, (int, float)) else "-"
        t.add_row(mark, f"[{style}]{name}[/{style}]" if style else name, durs, s.get("detail") or "")
    console.print(t)


def render_sanitized(scan: dict[str, Any], console: Console) -> None:
    msgs = scan.get("sanitized_messages") or []
    if not msgs:
        return
    txt = Text()
    content = msgs[-1].get("content", "")
    i = 0
    import re

    for m in re.finditer(r"\[[A-Z_]+_\d+\]", content):
        txt.append(content[i:m.start()])
        txt.append(m.group(0), style="bold yellow")
        i = m.end()
    txt.append(content[i:])
    console.print(Panel(txt, title="sent to the provider (sanitised)", title_align="left", border_style="yellow"))


def render_block(out: ChatOutcome, console: Console) -> None:
    body = Text()
    body.append(f"{out.error_code or 'BLOCKED'}\n", style="bold red")
    body.append(out.error_message or "The request was blocked by policy.")
    if out.scan:
        cats = sorted({d.get("category", "?") for d in out.scan.get("detections", [])})
        if cats:
            body.append(f"\n\ndetections: {', '.join(cats)}", style="dim")
    if out.request_id:
        body.append(f"\n\nappeal:  aegis appeal {out.request_id} \"<why this should be allowed>\"", style="dim")
    console.print(Panel(body, title="blocked -- nothing was sent to a provider", title_align="left", border_style="red"))


def render_footer(out: ChatOutcome, console: Console) -> None:
    tel = out.telemetry or {}
    g = out.grounding or {}
    parts = []
    if tel.get("provider_used"):
        parts.append(f"provider [bold]{tel['provider_used']}[/bold]"
                     + (" [yellow](failover)[/yellow]" if tel.get("failover_used") else ""))
    if "cache_hit" in tel:
        parts.append("cache [green]HIT[/green]" if tel["cache_hit"] else "cache MISS")
    if g.get("grounding"):
        gs = g["grounding"]
        parts.append(f"grounding {gs.get('status')} ({gs.get('score')})" if gs.get("status") else "")
        if g.get("rehydrated"):
            parts.append("rehydrated")
    if out.request_id:
        parts.append(f"[dim]{out.request_id}[/dim]")
    console.print("  ".join(p for p in parts if p))


def render_audit(audit: dict[str, Any], console: Console) -> None:
    t = Table(title="audit row", title_justify="left", title_style="bold", show_header=False, box=None, pad_edge=False)
    t.add_column(style="dim", min_width=18); t.add_column()
    keys = ("policy_action", "rules_fired", "policy_version", "provider", "model", "total_tokens",
            "latency_total_ms", "cache_hit", "failover_used", "grounding_score", "estimated_cost_usd")
    for k in keys:
        if k in audit and audit[k] is not None:
            v = audit[k]
            t.add_row(k, ", ".join(v) if isinstance(v, list) else str(v))
    console.print(t)
    console.print("[dim]cost is an estimate from config/pricing.yaml list prices; energy/CO2 from config/sustainability.yaml assumptions[/dim]")
