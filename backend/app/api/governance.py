"""Governance endpoints: policies, human review, and fairness.

These three surfaces carry Requirements 7, 1 and 5 respectively. They are the
difference between an AI security gateway and a responsible-AI gateway.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.hardening import require_admin, require_reviewer

from app.config import settings
from app.contracts.common import ReviewStatus
from app.contracts.governance import (
    FairnessReportResponse,
    PolicyHistoryResponse,
    PolicyResponse,
    PolicyRollbackRequest,
    PolicyUpdateRequest,
    PolicyVersionSummary,
    ReviewCreateRequest,
    ReviewCreateResponse,
    ReviewDecisionRequest,
    ReviewDecisionResponse,
    ReviewListResponse,
    ReviewRecord,
)
from app.fairness import harness as fairness
from app.policies import service as policies
from app.reviews import service as reviews
from app.utils.logging import get_logger

router = APIRouter(prefix="/api", tags=["governance"])
log = get_logger(__name__)

# Appealability is a policy property, read from config/policies.yaml via the
# engine -- never a hardcoded set here. A leaked credential is not appealable
# because the policy says so, and a tenant may change that in the file.


# ---------------------------------------------------------------------------
# Policies  (Requirement 7 -- accountability)
# ---------------------------------------------------------------------------


@router.get("/policies", response_model=PolicyResponse, summary="Current policy config")
async def get_policies() -> PolicyResponse:
    """The policy in force: YAML verbatim, version, profiles, and when it was set."""
    return policies.current()


@router.put(
    "/policies",
    response_model=PolicyResponse,
    summary="Update policy, creating a new immutable version",
    description=(
        "Validates the document through the engine's own loader, assigns the "
        "next version number (stamped into the YAML), writes an immutable "
        "`policy_version` row, writes the live file, and reloads the engine. "
        "Previous versions are never mutated, so any past decision can be "
        "replayed against the rules that were in force: the audit row records "
        "`policy_version`, and history says what that version contained.\n\n"
        "An invalid document is rejected with the loader's message and nothing "
        "changes. `author_ref` is stored as a salted hash."
    ),
)
async def put_policies(req: PolicyUpdateRequest, _: None = Depends(require_admin)) -> PolicyResponse:
    try:
        return policies.update(req.yaml_body, author_ref=req.author_ref, note=req.note)
    except policies.PolicyInvalid as exc:
        raise HTTPException(status_code=422, detail=f"policy document invalid: {exc}") from exc


@router.get(
    "/policies/history",
    response_model=PolicyHistoryResponse,
    summary="Policy version history, newest first",
)
async def policy_history(limit: int = Query(50, ge=1, le=500)) -> PolicyHistoryResponse:
    return PolicyHistoryResponse(versions=policies.history(limit))


@router.get(
    "/policies/versions/{version}",
    response_model=PolicyResponse,
    summary="The YAML body of one historical version",
)
async def policy_version(version: int) -> PolicyResponse:
    try:
        body = policies.get_version_body(version)
    except policies.PolicyVersionNotFound:
        raise HTTPException(status_code=404, detail="No such policy version")
    now = policies.current()
    return PolicyResponse(
        version=version, profile=now.profile, available_profiles=now.available_profiles,
        yaml_body=body, updated_at=None,
    )


@router.post(
    "/policies/rollback/{version}",
    response_model=PolicyResponse,
    summary="Roll back to a previous version (as a new version)",
    description=(
        "History is never rewritten. Rollback creates a NEW version whose body "
        "is the old one, noted as a rollback, so the sequence of what was in "
        "force stays linear and complete."
    ),
)
async def policy_rollback(
    version: int, req: PolicyRollbackRequest | None = None, _: None = Depends(require_admin)
) -> PolicyResponse:
    try:
        return policies.rollback(
            version,
            author_ref=req.author_ref if req else None,
            note=req.note if req else None,
        )
    except policies.PolicyVersionNotFound:
        raise HTTPException(status_code=404, detail="No such policy version")
    except policies.PolicyInvalid as exc:
        raise HTTPException(status_code=422, detail=f"stored version is invalid: {exc}") from exc



# ---------------------------------------------------------------------------
# Human review  (Requirement 1 -- human agency and oversight)
# ---------------------------------------------------------------------------


@router.post(
    "/reviews",
    response_model=ReviewCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Appeal an automated block",
    description=(
        "Aegis makes automated decisions that affect people, which makes Aegis "
        "itself subject to the oversight principle it enforces. Any appealable "
        "block can be contested here with a written justification.\n\n"
        "Refused, with the reason, when the rule is not appealable under the "
        "current policy (credential leaks) or when the audit log shows the "
        "request was not blocked. One pending review per request; a repeat "
        "returns the existing one."
    ),
)
async def create_review(req: ReviewCreateRequest) -> ReviewCreateResponse:
    out = reviews.create_review(req)
    return ReviewCreateResponse(review=out.record, accepted=out.accepted, reason=out.reason)


@router.get("/reviews", response_model=ReviewListResponse, summary="Review queue")
async def list_reviews(
    status_filter: ReviewStatus | None = Query(None, alias="status"),
    tenant_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> ReviewListResponse:
    items, total = reviews.list_reviews(status=status_filter, tenant_id=tenant_id,
                                        limit=limit, offset=offset)
    return ReviewListResponse(items=items, total=total)


@router.get("/reviews/{review_id}", response_model=ReviewRecord, summary="One review")
async def get_review(review_id: str) -> ReviewRecord:
    rec = reviews.get_review(review_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return rec


@router.post(
    "/reviews/{review_id}/decision",
    response_model=ReviewDecisionResponse,
    summary="Human approves or denies an appeal",
    description=(
        "Approval mints a short-lived, single-use override token scoped to the "
        "one `request_id` under review. The token is returned in this response "
        "exactly once and stored hashed. The Gateway replays the same "
        "`request_id` with `override_token` set; `/inspect` lifts the "
        "appealable block, records the override, and consumes the token.\n\n"
        "Reviewer identity (`reviewer_ref`) is stored as a salted hash. "
        "Authentication of reviewers is Phase 16."
    ),
)
async def decide_review(
    review_id: str, req: ReviewDecisionRequest, _: None = Depends(require_reviewer)
) -> ReviewDecisionResponse:
    try:
        out = reviews.decide(
            review_id, approve=req.approve, reviewer_ref=req.reviewer_ref, note=req.reviewer_note,
        )
    except reviews.ReviewNotFound:
        raise HTTPException(status_code=404, detail="Review not found")
    except reviews.ReviewNotPending as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return ReviewDecisionResponse(
        review=out.record, override_token=out.override_token, override_expires_at=out.override_expires_at,
    )



# ---------------------------------------------------------------------------
# Fairness  (Requirement 5 -- diversity, non-discrimination and fairness)
# ---------------------------------------------------------------------------


@router.get(
    "/fairness/report",
    response_model=FairnessReportResponse,
    summary="Detector recall across population groups",
    description=(
        "Measured PERSON-detector recall per name-origin group, for two "
        "configurations: `baseline` (stock NER only) and `current` (the full "
        "scanner). The gap is best-group recall minus worst-group recall; "
        "`deltas` shows each group's change so a lift in one group is visible "
        "even when the overall gap is set by another.\n\n"
        "A privacy tool that protects some people's identities more reliably "
        "than others is an unfair system. Aegis measures its own gap and "
        "publishes it -- including when the measurement contradicts what the "
        "team expected.\n\n"
        "Returns nulls until a run has been recorded (`POST /api/fairness/run`). "
        "The numbers are measured, never assumed."
    ),
)
async def fairness_report(detector: str = Query("pii.person")) -> FairnessReportResponse:
    return fairness.build_report(detector)


@router.post(
    "/fairness/run",
    response_model=FairnessReportResponse,
    summary="Run the fairness harness now and persist the result",
    description=(
        "Runs baseline (gazetteer disabled) and current (full scanner) over "
        "the corpus in `eval/name_corpus.yaml` and persists both. The full "
        "corpus is 1,800 samples per configuration and takes a few seconds "
        "per run on the large spaCy model; `max_templates` and `max_names` "
        "shorten it for a smoke test."
    ),
)
async def fairness_run(
    max_templates: int | None = Query(None, ge=1, le=20),
    max_names: int | None = Query(None, ge=1, le=500),
) -> FairnessReportResponse:
    fairness.run_both(max_templates=max_templates, max_names=max_names)
    return fairness.build_report()
