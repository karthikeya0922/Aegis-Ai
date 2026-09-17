"""Contracts for the audit write path and the audit read APIs.

Field allowlist discipline: the write model below is the *only* shape accepted
by POST /audit/events. Raw prompt text, keys, passwords and unhashed user
identifiers have no field to land in, by construction.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.contracts.common import Decision, GroundingStatus, StrictModel


class AuditEventRequest(StrictModel):
    request_id: str
    tenant_id: str = "default"
    user_ref: str | None = None  # hashed on write, never persisted raw

    provider: str | None = None
    model: str | None = None
    routed_complexity: str | None = None

    latency_total_ms: float | None = None
    latency_inspect_ms: float | None = None
    latency_provider_ms: float | None = None

    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None

    cache_hit: bool = False
    cache_similarity: float | None = None

    pii_detected: bool = False
    pii_count: int = 0
    pii_types: list[str] = Field(default_factory=list)

    secret_detected: bool = False
    secret_count: int = 0
    secret_types: list[str] = Field(default_factory=list)

    injection_detected: bool = False
    injection_score: float | None = None

    policy_action: Decision | None = None
    policy_version: int | None = None
    rules_fired: list[str] = Field(default_factory=list)

    failover_used: bool = False
    failover_from: str | None = None
    failover_to: str | None = None

    egress_flagged: bool = False
    egress_categories: list[str] = Field(default_factory=list)

    grounding_enabled: bool = False
    grounding_score: float | None = None
    grounding_status: GroundingStatus | None = None

    estimated_cost_usd: float | None = None
    estimated_savings_usd: float | None = None
    estimated_energy_wh: float | None = None
    estimated_co2_g: float | None = None

    review_id: str | None = None


class AuditEventResponse(StrictModel):
    stored: bool
    request_id: str
    duplicate: bool = False


class AuditEventRecord(StrictModel):
    """Read-side projection. Deliberately narrower than the write model."""

    id: int
    request_id: str
    tenant_id: str
    timestamp: datetime
    provider: str | None = None
    model: str | None = None
    policy_action: str | None = None
    rules_fired: list[str] = Field(default_factory=list)
    pii_count: int = 0
    secret_count: int = 0
    injection_detected: bool = False
    cache_hit: bool = False
    failover_used: bool = False
    grounding_score: float | None = None
    latency_total_ms: float | None = None
    total_tokens: int | None = None
    estimated_cost_usd: float | None = None
    review_id: str | None = None


class AuditEventPage(StrictModel):
    items: list[AuditEventRecord]
    total: int
    limit: int
    offset: int


class AuditReportSection(StrictModel):
    title: str
    requirement: str | None = None
    rows: list[dict] = Field(default_factory=list)
    note: str | None = None


class AuditReport(StrictModel):
    generated_at: datetime
    window_start: datetime | None = None
    window_end: datetime | None = None
    tenant_id: str
    sections: list[AuditReportSection]
    disclaimer: str
