"""Dashboard metrics APIs."""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.contracts.metrics import (
    MetricsResponse,
    ProviderMetricsResponse,
    SecurityMetricsResponse,
    SustainabilityMetricsResponse,
)
from app.stubs import (
    stub_metrics,
    stub_provider_metrics,
    stub_security_metrics,
    stub_sustainability_metrics,
)

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("", response_model=MetricsResponse, summary="Aggregate platform metrics")
async def metrics(window_hours: int = Query(24, ge=1, le=8760)) -> MetricsResponse:
    return stub_metrics(window_hours)


@router.get(
    "/security",
    response_model=SecurityMetricsResponse,
    summary="Security and oversight counters",
)
async def security_metrics(
    window_hours: int = Query(24, ge=1, le=8760),
) -> SecurityMetricsResponse:
    return stub_security_metrics(window_hours)


@router.get(
    "/sustainability",
    response_model=SustainabilityMetricsResponse,
    summary="Cache efficiency and estimated environmental figures",
    description=(
        "Energy and CO2 values are **estimates**, derived from configurable "
        "per-token assumptions and a grid intensity factor -- not measurements. "
        "The `basis` and `disclaimer` fields must be surfaced in the UI wherever "
        "these numbers appear."
    ),
)
async def sustainability_metrics(
    window_hours: int = Query(24, ge=1, le=8760),
) -> SustainabilityMetricsResponse:
    return stub_sustainability_metrics(window_hours)


@router.get(
    "/providers",
    response_model=ProviderMetricsResponse,
    summary="Per-provider health and failover telemetry",
)
async def provider_metrics(
    window_hours: int = Query(24, ge=1, le=8760),
) -> ProviderMetricsResponse:
    return stub_provider_metrics(window_hours)
