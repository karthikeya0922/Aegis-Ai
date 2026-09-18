"""Dashboard metrics APIs. Real as of Phase 12: every number is an aggregate
over request_audit, and every estimate carries its basis."""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.audit import metrics
from app.contracts.metrics import (
    MetricsResponse,
    ProviderMetricsResponse,
    SecurityMetricsResponse,
    SustainabilityMetricsResponse,
)

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("", response_model=MetricsResponse, summary="Aggregate platform metrics")
async def overview(
    tenant_id: str = Query("default"),
    window_hours: int = Query(24, ge=1, le=8760),
) -> MetricsResponse:
    return metrics.overview(tenant_id, window_hours)


@router.get(
    "/security",
    response_model=SecurityMetricsResponse,
    summary="Security and oversight counters",
)
async def security(
    tenant_id: str = Query("default"),
    window_hours: int = Query(24, ge=1, le=8760),
) -> SecurityMetricsResponse:
    return metrics.security(tenant_id, window_hours)


@router.get(
    "/sustainability",
    response_model=SustainabilityMetricsResponse,
    summary="Cache efficiency and estimated environmental figures",
    description=(
        "Energy and CO2 values are **estimates**, derived from configurable "
        "per-token assumptions and a grid intensity factor -- not measurements. "
        "The `basis` and `disclaimer` fields must be surfaced in the UI wherever "
        "these numbers appear. Avoided figures on cache hits are counted against "
        "a named counterfactual model."
    ),
)
async def sustainability(
    tenant_id: str = Query("default"),
    window_hours: int = Query(24, ge=1, le=8760),
) -> SustainabilityMetricsResponse:
    return metrics.sustainability(tenant_id, window_hours)


@router.get(
    "/providers",
    response_model=ProviderMetricsResponse,
    summary="Per-provider volume, failover and latency",
)
async def providers(
    tenant_id: str = Query("default"),
    window_hours: int = Query(24, ge=1, le=8760),
) -> ProviderMetricsResponse:
    return metrics.providers(tenant_id, window_hours)
