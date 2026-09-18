"""aegis status against recorded Inspector responses -- no network."""

from __future__ import annotations

import httpx
from rich.console import Console

from aegis_cli import status as St
from aegis_cli.config import CLIConfig

RESPONSES = {
    "/api/health": {"status": "degraded", "phase": "phase-0.1.0+abc", "uptime_seconds": 12.0,
                    "components": [{"name": "pii_scanner", "status": "ok", "detail": ""},
                                   {"name": "hardening", "status": "degraded", "detail": "admin UNAUTHENTICATED"}]},
    "/api/metrics": {"window_hours": 24, "total_requests": 5, "blocked_requests": 2, "sanitized_requests": 1,
                     "latency": {"p50_ms": 100.0, "p95_ms": 200.0, "inspector_overhead_p50_ms": 9.1},
                     "tokens": {"total_tokens": 42}, "cost": {"estimated_spend_usd": 0.001, "estimated_saved_usd": 0.0,
                                                              "basis": "list prices, not an invoice"}},
    "/api/metrics/security": {"pii_detections": 3, "secret_detections": 1, "credential_blocks": 1, "injection_blocks": 1,
                              "egress_flags": 0, "top_rules": [{"rule_id": "pii", "count": 3}]},
    "/api/metrics/sustainability": {"cache_hit_rate": 0.5, "cache_hits": 1, "cache_misses": 1, "estimated_energy_wh": 0.1,
                                    "estimated_co2_g": 0.05, "estimated_energy_avoided_wh": 0.1, "estimated_co2_avoided_g": 0.05,
                                    "basis": "assumed energy per token"},
    "/api/metrics/providers": {"providers": [{"provider": "groq", "requests": 4, "failures": 0, "failover_in": 0,
                                              "failover_out": 1, "last_seen": "2026-09-18T00:00:00"}], "failover_events": 1},
    "/api/reviews": {"items": [], "total": 2},
    "/api/fairness/report": {"current": {"groups": [{"group": "indian", "recall": 0.95}, {"group": "east_asian", "recall": 0.81}],
                                         "recall_gap": 0.14}, "gap_closed": 0.0,
                             "disclaimer": "synthetic corpus, not a population sample"},
}


def _engine():
    def handler(req: httpx.Request) -> httpx.Response:
        body = RESPONSES.get(req.url.path)
        return httpx.Response(200, json=body) if body is not None else httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="http://engine")


def _gateway(ok: bool):
    def handler(req: httpx.Request) -> httpx.Response:
        if not ok:
            raise httpx.ConnectError("refused", request=req)
        return httpx.Response(200, json={"range": "24h"})
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="http://gw")


def test_collect_and_render_show_estimates_with_basis_and_the_open_gap():
    snap = St.collect(CLIConfig(), client=_engine(), gateway_client=_gateway(True))
    assert snap.gateway_ok and snap.errors == {} and snap.reviews["total"] == 2
    console = Console(record=True, width=120, force_terminal=False)
    St.render(snap, CLIConfig(), console)
    text = console.export_text()
    assert "degraded" in text and "UNAUTHENTICATED" in text
    assert "list prices, not an invoice" in text and "assumed energy per token" in text
    assert "50.0%" in text and "groq" in text and "failover events: 1" in text
    assert "pending: 2" in text and "aegis reviews list" in text
    assert "east_asian 0.810" in text and "gap 0.140" in text and "gap_closed 0.0" in text
    assert "synthetic corpus" in text


def test_unreachable_services_are_reported_not_fatal():
    def down(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)
    snap = St.collect(CLIConfig(), client=httpx.Client(transport=httpx.MockTransport(down), base_url="http://e"),
                      gateway_client=_gateway(False))
    assert snap.health is None and snap.gateway_ok is False and snap.errors["health"] == "ConnectError"
    console = Console(record=True, width=120, force_terminal=False)
    St.render(snap, CLIConfig(), console)
    assert "unreachable" in console.export_text()
