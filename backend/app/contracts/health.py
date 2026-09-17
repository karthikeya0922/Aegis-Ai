"""Contract for GET /api/health."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.contracts.common import StrictModel


class ComponentHealth(StrictModel):
    name: str
    status: Literal["ok", "degraded", "unavailable", "stub"]
    detail: str | None = None


class HealthResponse(StrictModel):
    service: str
    version: str
    status: Literal["ok", "degraded", "unavailable"]
    phase: str = Field(description="Which build phase this deployment implements")
    degraded_reasons: list[str] = Field(default_factory=list)
    components: list[ComponentHealth] = Field(default_factory=list)
    uptime_seconds: float = 0.0
