"""Governance endpoints: policies, human review, and fairness.

These three surfaces carry Requirements 7, 1 and 5 respectively. They are the
difference between an AI security gateway and a responsible-AI gateway.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query, status

from app.config import settings
from app.contracts.common import ReviewStatus
from app.contracts.governance import (
    FairnessReportResponse,
    PolicyHistoryResponse,
    PolicyResponse,
    PolicyUpdateRequest,
    PolicyVersionSummary,
    ReviewCreateRequest,
    ReviewCreateResponse,
    ReviewDecisionRequest,
    ReviewDecisionResponse,
    ReviewListResponse,
)
from app.stubs import stub_fairness_report, stub_policy, stub_review_record, stub_reviews
from app.utils.ids import override_token
from app.utils.logging import get_logger

router = APIRouter(prefix="/api", tags=["governance"])
log = get_logger(__name__)

# Rules that may never be appealed. A leaked credential is a fact, not a
# judgement call, so there is nothing for a human to weigh.
NON_APPEALABLE_RULES = {
    "secrets.credentials",
    "secrets.aws_credentials",
    "secrets.database_credentials",
    "secrets.private_keys",
}


# ---------------------------------------------------------------------------
# Policies  (Requirement 7 -- accountability)
# ---------------------------------------------------------------------------


@router.get("/policies", response_model=PolicyResponse, summary="Current policy config")
async def get_policies(profile: str | None = Query(None)) -> PolicyResponse:
    return stub_policy()


@router.put(
    "/policies",
    response_model=PolicyResponse,
    summary="Update policy, creating a new immutable version",
    description=(
        "Policy changes are themselves auditable. Each update writes a new "
        "`policy_version` row; previous versions are never mutated, so any "
        "past decision can be replayed against the rules that were in force."
    ),
)
async def put_policies(req: PolicyUpdateRequest) -> PolicyResponse:
    current = stub_policy()
    log.info("policy update requested (phase 0 stub: not persisted)")
    return current


@router.get(
    "/policies/history",
    response_model=PolicyHistoryResponse,
    summary="Policy version history",
)
async def policy_history() -> PolicyHistoryResponse:
    return PolicyHistoryResponse(
        versions=[
            PolicyVersionSummary(
                version=1,
                created_at=datetime.now(timezone.utc),
                diff_summary="initial",
                note="Phase 0 baseline",
            )
        ]
    )


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
        "block can be contested here with a written justification."
    ),
)
async def create_review(req: ReviewCreateRequest) -> ReviewCreateResponse:
    if req.rule_fired in NON_APPEALABLE_RULES:
        return ReviewCreateResponse(
            review=stub_review_record(req.request_id, req.user_justification),
            accepted=False,
            reason=(
                "Credential-leak blocks are not appealable. The detected value "
                "should be rotated, and the prompt resubmitted without it."
            ),
        )
    record = stub_review_record(req.request_id, req.user_justification)
    log.info(
        "review opened request_id=%s rule=%s",
        req.request_id,
        req.rule_fired or "-",
        extra={"request_id": req.request_id},
    )
    return ReviewCreateResponse(review=record, accepted=True)


@router.get("/reviews", response_model=ReviewListResponse, summary="Review queue")
async def list_reviews(
    status_filter: ReviewStatus | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=500),
) -> ReviewListResponse:
    return stub_reviews()


@router.post(
    "/reviews/{review_id}/decision",
    response_model=ReviewDecisionResponse,
    summary="Human approves or denies an appeal",
    description=(
        "Approval mints a short-lived, single-use override token scoped to the "
        "one `request_id` under review. The Gateway replays that request with "
        "the token; `/inspect` honours it once and records the override."
    ),
)
async def decide_review(
    review_id: str, req: ReviewDecisionRequest
) -> ReviewDecisionResponse:
    if not review_id.startswith("rev_"):
        raise HTTPException(status_code=404, detail="Review not found")

    record = stub_review_record("req_stub", "phase 0 stub")
    record.id = review_id
    record.status = ReviewStatus.APPROVED if req.approve else ReviewStatus.DENIED
    record.reviewer_note = req.reviewer_note
    record.decided_at = datetime.now(timezone.utc)

    token = None
    expires = None
    if req.approve:
        token = override_token()
        expires = datetime.now(timezone.utc) + timedelta(
            seconds=settings.override_token_ttl_seconds
        )
        record.override_expires_at = expires

    log.info("review %s decided approve=%s", review_id, req.approve)
    return ReviewDecisionResponse(
        review=record, override_token=token, override_expires_at=expires
    )


# ---------------------------------------------------------------------------
# Fairness  (Requirement 5 -- diversity, non-discrimination and fairness)
# ---------------------------------------------------------------------------


@router.get(
    "/fairness/report",
    response_model=FairnessReportResponse,
    summary="Detector recall across population groups",
    description=(
        "Reports measured PII-detector recall per name-origin group, and the "
        "gap between the best- and worst-served group.\n\n"
        "A privacy tool that protects some people's identities more reliably "
        "than others is an unfair system. Aegis measures its own gap and "
        "publishes it, including the baseline where it was worse.\n\n"
        "Returns nulls until Phase 13 -- the numbers are measured, never "
        "assumed."
    ),
)
async def fairness_report(detector: str = Query("pii.person")) -> FairnessReportResponse:
    return stub_fairness_report()
