"""Contracts for the dashboard read APIs.

Every estimated figure carries a `basis` string naming its assumption. An
estimate without a stated baseline is fabricated telemetry -- see spec s11.
"""

from __future__ import annotations

from pydantic import Field

from app.contracts.common import StrictModel


class LatencyStats(StrictModel):
    p50_ms: float | None = None
    p95_ms: float | None = None
    p99_ms: float | None = None
    mean_ms: float | None = None
    inspector_overhead_p50_ms: float | None = None
    inspector_overhead_p95_ms: float | None = None


class TokenStats(StrictModel):
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


class CostStats(StrictModel):
    estimated_spend_usd: float = 0.0
    estimated_saved_usd: float = 0.0
    basis: str


class MetricsResponse(StrictModel):
    window_hours: int
    total_requests: int = 0
    blocked_requests: int = 0
    sanitized_requests: int = 0
    latency: LatencyStats = Field(default_factory=LatencyStats)
    tokens: TokenStats = Field(default_factory=TokenStats)
    cost: CostStats


class RuleCount(StrictModel):
    rule_id: str
    count: int


class SecurityMetricsResponse(StrictModel):
    window_hours: int
    pii_detections: int = 0
    secret_detections: int = 0
    injection_blocks: int = 0
    credential_blocks: int = 0
    egress_flags: int = 0
    reviews_pending: int = 0
    reviews_approved: int = 0
    reviews_denied: int = 0
    top_rules: list[RuleCount] = Field(default_factory=list)


class SustainabilityMetricsResponse(StrictModel):
    window_hours: int
    cache_hit_rate: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    estimated_energy_wh: float = 0.0
    estimated_co2_g: float = 0.0
    estimated_energy_avoided_wh: float = 0.0
    estimated_co2_avoided_g: float = 0.0
    basis: str
    disclaimer: str = (
        "Estimated, not measured. Derived from configurable per-token energy "
        "assumptions and a regional grid intensity factor."
    )


class ProviderStat(StrictModel):
    provider: str
    requests: int = 0
    failures: int = 0
    failover_in: int = 0
    failover_out: int = 0
    latency_p50_ms: float | None = None
    last_seen: str | None = None


class ProviderMetricsResponse(StrictModel):
    window_hours: int
    providers: list[ProviderStat] = Field(default_factory=list)
    failover_events: int = 0
