"""Health and readiness.

Reports honestly which subsystems are loaded and which are degraded, so
Person 2 can tell at a glance what a given deployment actually implements.

Components register themselves in COMPONENTS; the endpoint iterates the
registry. Adding a subsystem means adding one function and one line here,
and the list in the response can never drift from the list of probes.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from functools import lru_cache

from fastapi import APIRouter

from app.config import settings
from app.contracts.health import ComponentHealth, HealthResponse
from app.audit import database as audit_db
from app.audit import service as audit_service
from app.security.injection import get_detector as get_injection_detector
from app.security.secret_scanner import get_scanner as get_secret_scanner
from app.security.pii_scanner import get_pii_scanner
from app.security.policy_engine import get_policy_engine

router = APIRouter(tags=["health"])

_STARTED = time.monotonic()


@lru_cache
def build_phase() -> str:
    """`phase-<version>+<git sha>` derived at first call, never hand-bumped.

    The prefix keeps the contract test stable; the sha says which build is
    answering. Without git (a container built from a tarball) the sha is
    'unknown', which is honest.
    """
    sha = "unknown"
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=2, cwd=str(settings.policies_path.parent.parent),
        )
        if out.returncode == 0 and out.stdout.strip():
            sha = out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return f"phase-{settings.version}+{sha}"


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


def _database_component() -> ComponentHealth:
    if not audit_db.ping():
        return ComponentHealth(name="database", status="unavailable", detail="ping failed")
    st = audit_service.stats()
    return ComponentHealth(
        name="database",
        status="ok",
        detail=(
            f"{audit_db.backend_name()}, {audit_service.count_rows()} audit row(s); "
            f"writes: {st.inspections_recorded} inspections, {st.events_upserted} events, "
            f"{st.failures} failure(s)"
        ),
    )


def _fairness_component() -> ComponentHealth:
    from app.fairness import harness as fairness

    rows = fairness.latest_run(fairness.CURRENT_LABEL)
    if not rows:
        return ComponentHealth(
            name="fairness_harness", status="ok",
            detail="harness ready; no run recorded yet (POST /api/fairness/run)",
        )
    recalls = {r.group: r.recall for r in rows}
    worst = min(recalls, key=recalls.get)
    return ComponentHealth(
        name="fairness_harness", status="ok",
        detail=(
            f"last run {rows[0].run_at:%Y-%m-%d %H:%M} UTC over {len(rows)} groups; "
            f"gap {max(recalls.values()) - min(recalls.values()):.3f}, worst-served: {worst} "
            f"({recalls[worst]:.3f})"
        ),
    )


def _pending_reviews() -> int:
    from app.reviews import service as reviews

    try:
        return reviews.pending_count()
    except Exception:  # noqa: BLE001 - health must not fail
        return -1


def _metrics_component() -> ComponentHealth:
    from app.audit import metrics
    from app.audit.estimates import get_pricing, get_sustainability

    try:
        ov = metrics.overview(window_hours=24)
        return ComponentHealth(
            name="metrics", status="ok",
            detail=(
                f"aggregated over request_audit; {ov.total_requests} request(s) in the last 24h; "
                f"pricing v{get_pricing().version} ({get_pricing().as_of}), "
                f"sustainability v{get_sustainability().version} region={get_sustainability().region}"
            ),
        )
    except Exception as exc:  # noqa: BLE001
        return ComponentHealth(name="metrics", status="degraded", detail=type(exc).__name__)


def _policy_versions() -> int:
    from app.policies import service as policies

    try:
        return policies.version_count()
    except Exception:  # noqa: BLE001
        return -1


def _embeddings_component() -> ComponentHealth:
    from app.cache.embeddings import get_embedding_service

    e = get_embedding_service().health()
    if e["degraded"]:
        return ComponentHealth(
            name="embeddings", status="degraded",
            detail=f"hash fallback (no semantic structure): {e['degraded_reason']}",
        )
    return ComponentHealth(
        name="embeddings", status="ok",
        detail=f"sentence-transformers {e['model']}, dim {e['dim']}, L2-normalised",
    )


def _grounding_component() -> ComponentHealth:
    from app.verification.grounding import get_verifier

    g = get_verifier().health()
    if g["degraded"]:
        return ComponentHealth(
            name="grounding", status="degraded",
            detail=f"verification skipped (reported, never faked): {g['degraded_reason']}",
        )
    return ComponentHealth(
        name="grounding", status="ok",
        detail=f"NLI cross-encoder {g['model']}, labels read from model config; support score, not a guarantee",
    )


def _screens_component() -> ComponentHealth:
    from app.verification.screens import load_screens

    sc = load_screens()
    return ComponentHealth(
        name="egress_screens", status="ok",
        detail=(
            f"heuristic harm ({len(sc.harm.categories)} categories) and bias "
            f"({len(sc.bias.categories)} categories) screens, config v{sc.version}; pattern-based, not a classifier"
        ),
    )


def _secret_component() -> ComponentHealth:
    sc = get_secret_scanner()
    return ComponentHealth(
        name="secret_scanner", status="ok",
        detail=f"{len(sc.patterns)} config-driven patterns, overlap-resolved, entropy-weighted",
    )


def _entropy_component() -> ComponentHealth:
    return ComponentHealth(
        name="entropy_scanner", status="ok",
        detail=f"Shannon entropy >= {settings.entropy_threshold} over literals >= {settings.entropy_min_length} chars; warn-only by design",
    )


def _injection_component() -> ComponentHealth:
    det = get_injection_detector()
    return ComponentHealth(
        name="injection_detector", status="ok",
        detail=(
            f"heuristic, {len(det.ruleset.rules)} rules across "
            f"{len(det.ruleset.categories)} OWASP LLM01 categories; "
            "does not claim to catch novel attacks"
        ),
    )


def _policy_component() -> ComponentHealth:
    pol = get_policy_engine().policies
    return ComponentHealth(
        name="policy_engine", status="ok",
        detail=(
            f"config/policies.yaml v{pol.version}, profiles: {', '.join(pol.profiles)}; "
            f"{_policy_versions()} version(s) on file; hot-reloaded"
        ),
    )


def _review_component() -> ComponentHealth:
    return ComponentHealth(
        name="review_api", status="ok",
        detail=(
            f"{_pending_reviews()} pending; override tokens single-use, request-scoped, "
            f"{settings.override_token_ttl_seconds}s TTL, stored hashed"
        ),
    )


def _hardening_component() -> ComponentHealth:
    open_roles = [r for r, t in (("reviewer", settings.reviewer_token), ("admin", settings.admin_token)) if not t]
    limiter = (
        f"{settings.rate_limit_per_minute}/min burst {settings.rate_limit_burst} per tenant"
        if settings.rate_limit_per_minute > 0 else "rate limit OFF"
    )
    timeout = f"{settings.request_timeout_seconds:g}s deadline" if settings.request_timeout_seconds > 0 else "no deadline"
    if open_roles:
        return ComponentHealth(
            name="hardening", status="degraded",
            detail=f"{', '.join(open_roles)} endpoints UNAUTHENTICATED (token not set); {limiter}; {timeout}",
        )
    return ComponentHealth(name="hardening", status="ok", detail=f"reviewer + admin tokens set; {limiter}; {timeout}")


# The registry. Order is the order in the response.
COMPONENTS: tuple[Callable[[], ComponentHealth], ...] = (
    _pii_component,
    _secret_component,
    _entropy_component,
    _injection_component,
    _policy_component,
    _embeddings_component,
    _grounding_component,
    _screens_component,
    _database_component,
    _fairness_component,
    _metrics_component,
    _review_component,
    _hardening_component,
)


def _components() -> list[ComponentHealth]:
    out: list[ComponentHealth] = []
    for probe in COMPONENTS:
        try:
            out.append(probe())
        except Exception as exc:  # noqa: BLE001 - one broken probe must not hide the rest
            out.append(ComponentHealth(
                name=probe.__name__.strip("_").removesuffix("_component"),
                status="unavailable", detail=f"probe raised {type(exc).__name__}",
            ))
    return out


@router.get(
    "/api/health",
    response_model=HealthResponse,
    summary="Service health and subsystem readiness",
)
async def health() -> HealthResponse:
    components = _components()
    not_ok = [c for c in components if c.status != "ok"]
    reasons = [f"{c.name}: {c.detail}" for c in not_ok]
    return HealthResponse(
        service=settings.service_name,
        version=settings.version,
        status="degraded" if not_ok else "ok",
        phase=build_phase(),
        degraded_reasons=reasons,
        components=components,
        uptime_seconds=round(time.monotonic() - _STARTED, 2),
    )
