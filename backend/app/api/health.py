"""Health and readiness.

Reports honestly which subsystems are real and which are still stubs, so
Person 2 can tell at a glance what a given deployment actually implements.
"""

from __future__ import annotations

import time

from fastapi import APIRouter

from app.config import settings
from app.contracts.health import ComponentHealth, HealthResponse
from app.stubs import STUB_MODE

router = APIRouter(tags=["health"])

_STARTED = time.monotonic()
BUILD_PHASE = "phase-1-secrets-entropy"


def _components() -> list[ComponentHealth]:
    stub = "stub" if STUB_MODE else "ok"
    return [
        ComponentHealth(name="pii_scanner", status=stub, detail="Presidio + spaCy lands in Phase 2"),
        ComponentHealth(name="secret_scanner", status="ok", detail="25 config-driven patterns, overlap-resolved"),
        ComponentHealth(name="entropy_scanner", status="ok", detail="Shannon entropy, warn-only by design"),
        ComponentHealth(name="injection_detector", status=stub, detail="Phase 4"),
        ComponentHealth(name="policy_engine", status=stub, detail="Phase 6"),
        ComponentHealth(name="embeddings", status=stub, detail="Deterministic stub vectors until Phase 9"),
        ComponentHealth(name="grounding", status=stub, detail="NLI cross-encoder lands in Phase 10"),
        ComponentHealth(name="database", status=stub, detail="SQLAlchemy models land in Phase 8"),
        ComponentHealth(name="fairness_harness", status=stub, detail="Phase 13"),
        ComponentHealth(name="review_api", status=stub, detail="Phase 14"),
    ]


@router.get(
    "/api/health",
    response_model=HealthResponse,
    summary="Service health and subsystem readiness",
)
async def health() -> HealthResponse:
    components = _components()
    stubbed = [c.name for c in components if c.status == "stub"]
    return HealthResponse(
        service=settings.service_name,
        version=settings.version,
        status="degraded" if stubbed else "ok",
        phase=BUILD_PHASE,
        degraded_reasons=(
            [f"{len(stubbed)} subsystem(s) still serving Phase 0 stubs"] if stubbed else []
        ),
        components=components,
        uptime_seconds=round(time.monotonic() - _STARTED, 2),
    )
