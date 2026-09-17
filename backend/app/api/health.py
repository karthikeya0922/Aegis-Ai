"""Health and readiness.

Reports honestly which subsystems are real and which are still stubs, so
Person 2 can tell at a glance what a given deployment actually implements.
"""

from __future__ import annotations

import time

from fastapi import APIRouter

from app.config import settings
from app.contracts.health import ComponentHealth, HealthResponse
from app.security.injection import get_detector as get_injection_detector
from app.security.pii_scanner import get_pii_scanner
from app.security.policy_engine import get_policy_engine

router = APIRouter(tags=["health"])

_STARTED = time.monotonic()
BUILD_PHASE = "phase-7-pipeline"


def _pii_component() -> ComponentHealth:
    """Honest about which engine is running. regex-only is *degraded*, not ok."""
    ph = get_pii_scanner().health()
    if ph["degraded"]:
        return ComponentHealth(
            name="pii_scanner", status="degraded", detail=ph["degraded_reason"]
        )
    return ComponentHealth(
        name="pii_scanner",
        status="ok",
        detail=(
            f"Presidio + spaCy {ph['spacy_model']}, {len(ph['entities_enabled'])} entity types, "
            f"India engine with {ph['india_gazetteer_names']}-name gazetteer"
        ),
    )


def _components() -> list[ComponentHealth]:
    stub = "stub"  # components below that have not shipped yet
    return [
        _pii_component(),
        ComponentHealth(name="secret_scanner", status="ok", detail="25 config-driven patterns, overlap-resolved"),
        ComponentHealth(name="entropy_scanner", status="ok", detail="Shannon entropy, warn-only by design"),
        ComponentHealth(
            name="injection_detector",
            status="ok",
            detail=(
                f"heuristic, {len(get_injection_detector().ruleset.rules)} rules across "
                f"{len(get_injection_detector().ruleset.categories)} OWASP LLM01 categories; "
                "does not claim to catch novel attacks"
            ),
        ),
        ComponentHealth(
            name="policy_engine",
            status="ok",
            detail=(
                f"config/policies.yaml v{get_policy_engine().policies.version}, "
                f"profiles: {', '.join(get_policy_engine().policies.profiles)}; hot-reloaded"
            ),
        ),
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
    degraded = [c for c in components if c.status == "degraded"]
    reasons: list[str] = []
    if stubbed:
        reasons.append(f"{len(stubbed)} subsystem(s) still serving Phase 0 stubs")
    for c in degraded:
        reasons.append(f"{c.name}: {c.detail}")
    return HealthResponse(
        service=settings.service_name,
        version=settings.version,
        status="degraded" if (stubbed or degraded) else "ok",
        phase=BUILD_PHASE,
        degraded_reasons=reasons,
        components=components,
        uptime_seconds=round(time.monotonic() - _STARTED, 2),
    )
