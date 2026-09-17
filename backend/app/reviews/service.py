"""Human review of automated blocks (Requirement 1 -- human agency and oversight).

Aegis makes automated decisions that affect people, which makes Aegis
itself subject to the oversight principle it enforces. This module is the
appeal path:

    blocked user  -> create_review(justification)      PENDING
    reviewer      -> decide(approve | deny, note)      APPROVED / DENIED
    approval      -> mints an override token           returned ONCE, stored hashed
    gateway       -> replays the same request_id with the token
    /inspect      -> verify(): approved, scoped, unexpired, unused -> lifts the
                     appealable block; consume(): single use

Guarantees the tests pin:

  * Appealability is a policy property (config/policies.yaml), never a
    hardcoded set here. A credential block is refused with the reason.
  * A request the audit log shows was not blocked cannot be appealed.
  * One pending review per request; a repeat returns the existing one.
  * The raw override token is never stored. Verification hashes the
    presented token and compares.
  * A token is scoped to exactly one request_id, expires after
    AEGIS_OVERRIDE_TOKEN_TTL_SECONDS, and is consumed on first successful
    use. Presenting it against a different request is a scope violation
    and is refused.
  * Reviewer and requester identities are stored as salted hashes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.audit.database import session_scope
from app.audit.models import RequestAudit, ReviewRequest
from app.audit.service import token_hash
from app.config import settings
from app.contracts.common import Decision, ReviewStatus
from app.contracts.governance import ReviewCreateRequest, ReviewRecord
from app.security.pipeline import OverrideResult
from app.security.policy_engine import get_policy_engine
from app.utils.ids import hash_user_ref, override_token as mint_token, review_id as new_review_id
from app.utils.logging import get_logger

log = get_logger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; treat them as UTC."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def to_record(row: ReviewRequest) -> ReviewRecord:
    return ReviewRecord(
        id=row.id,
        request_id=row.request_id,
        tenant_id=row.tenant_id,
        created_at=_aware(row.created_at),
        original_decision=Decision(row.original_decision),
        rule_fired=row.rule_fired,
        user_justification=row.user_justification,
        status=ReviewStatus(row.status),
        reviewer_note=row.reviewer_note,
        decided_at=_aware(row.decided_at),
        override_expires_at=_aware(row.override_expires_at),
    )


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


@dataclass
class CreateOutcome:
    record: ReviewRecord
    accepted: bool
    reason: str | None = None


def create_review(req: ReviewCreateRequest) -> CreateOutcome:
    engine = get_policy_engine()

    # Appealability comes from policy. A leaked credential is a fact, not a
    # judgement call, and the policy file says so.
    if req.rule_fired and not engine.is_appealable(req.rule_fired):
        placeholder = _unpersisted_record(req)
        return CreateOutcome(
            placeholder, accepted=False,
            reason=(
                f"Blocks under rule '{req.rule_fired}' are not appealable under the current "
                "policy. Rotate the detected value and resubmit without it."
            ),
        )

    with session_scope() as s:
        audit = s.execute(
            select(RequestAudit).where(RequestAudit.request_id == req.request_id)
        ).scalar_one_or_none()

        # If we have the decision on file and it was not a block, there is
        # nothing to appeal.
        if audit is not None and audit.policy_action != Decision.BLOCK.value:
            return CreateOutcome(
                _unpersisted_record(req), accepted=False,
                reason=(
                    f"Request {req.request_id} was not blocked (recorded decision: "
                    f"{audit.policy_action}); there is nothing to appeal."
                ),
            )

        existing = s.execute(
            select(ReviewRequest).where(
                ReviewRequest.request_id == req.request_id,
                ReviewRequest.status == ReviewStatus.PENDING.value,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return CreateOutcome(to_record(existing), accepted=True,
                                 reason="A review for this request is already pending.")

        row = ReviewRequest(
            id=new_review_id(),
            request_id=req.request_id,
            tenant_id=req.tenant_id,
            requester_ref_hash=hash_user_ref(req.user_ref),
            original_decision=req.original_decision.value,
            rule_fired=req.rule_fired,
            user_justification=req.user_justification,
            status=ReviewStatus.PENDING.value,
        )
        s.add(row)
        if audit is not None:
            audit.review_id = row.id
        s.flush()
        record = to_record(row)

    log.info("review %s opened for %s (rule=%s)", record.id, req.request_id, req.rule_fired or "-",
             extra={"request_id": req.request_id})
    return CreateOutcome(record, accepted=True)


def _unpersisted_record(req: ReviewCreateRequest) -> ReviewRecord:
    """Shape-complete record for a refused appeal. Nothing is written."""
    return ReviewRecord(
        id="rev_not_created",
        request_id=req.request_id,
        tenant_id=req.tenant_id,
        created_at=_now(),
        original_decision=req.original_decision,
        rule_fired=req.rule_fired,
        user_justification=req.user_justification,
        status=ReviewStatus.DENIED,
        reviewer_note=None,
        decided_at=None,
        override_expires_at=None,
    )


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def list_reviews(
    *,
    status: ReviewStatus | None = None,
    tenant_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[ReviewRecord], int]:
    with session_scope() as s:
        q = select(ReviewRequest)
        if status is not None:
            q = q.where(ReviewRequest.status == status.value)
        if tenant_id:
            q = q.where(ReviewRequest.tenant_id == tenant_id)
        total = s.execute(select(func.count()).select_from(q.subquery())).scalar_one()
        rows = s.execute(
            q.order_by(ReviewRequest.created_at.desc()).limit(limit).offset(offset)
        ).scalars().all()
        return [to_record(r) for r in rows], int(total)


def get_review(review_id: str) -> ReviewRecord | None:
    with session_scope() as s:
        row = s.get(ReviewRequest, review_id)
        return to_record(row) if row else None


def pending_count() -> int:
    with session_scope() as s:
        return int(s.execute(
            select(func.count()).select_from(ReviewRequest)
            .where(ReviewRequest.status == ReviewStatus.PENDING.value)
        ).scalar_one())


# ---------------------------------------------------------------------------
# Decide
# ---------------------------------------------------------------------------


class ReviewNotFound(LookupError):
    pass


class ReviewNotPending(ValueError):
    pass


@dataclass
class DecisionOutcome:
    record: ReviewRecord
    override_token: str | None
    override_expires_at: datetime | None


def decide(
    review_id: str, *, approve: bool, reviewer_ref: str | None, note: str | None
) -> DecisionOutcome:
    with session_scope() as s:
        row = s.get(ReviewRequest, review_id)
        if row is None:
            raise ReviewNotFound(review_id)
        if row.status != ReviewStatus.PENDING.value:
            raise ReviewNotPending(f"review {review_id} is already {row.status}")

        row.reviewer_ref_hash = hash_user_ref(reviewer_ref)
        row.reviewer_note = note
        row.decided_at = _now()

        token: str | None = None
        expires: datetime | None = None
        if approve:
            row.status = ReviewStatus.APPROVED.value
            token = mint_token()
            expires = row.decided_at + timedelta(seconds=settings.override_token_ttl_seconds)
            # Stored hashed. The raw token leaves this function exactly once.
            row.override_token_hash = token_hash(token)
            row.override_expires_at = expires
        else:
            row.status = ReviewStatus.DENIED.value
        s.flush()
        record = to_record(row)

    log.info("review %s %s", review_id, record.status.value, extra={"request_id": record.request_id})
    return DecisionOutcome(record, token, expires)


# ---------------------------------------------------------------------------
# Override verification -- plugs into the pipeline
# ---------------------------------------------------------------------------


class ReviewOverrideVerifier:
    """The real verifier. Replaces PermissiveOverrideVerifier (Phase 7)."""

    def verify(self, token: str | None, request_id: str) -> OverrideResult:
        if not token:
            return OverrideResult(False, "no token")
        h = token_hash(token)
        with session_scope() as s:
            row = s.execute(
                select(ReviewRequest).where(ReviewRequest.override_token_hash == h)
            ).scalar_one_or_none()
            if row is None:
                return OverrideResult(False, "unknown token")
            if row.status != ReviewStatus.APPROVED.value:
                return OverrideResult(False, f"review is {row.status}, not approved")
            if row.request_id != request_id:
                # Scope violation: the token exists but was minted for a
                # different request. Refused, and logged as such.
                log.warning("override token for %s presented against %s", row.request_id, request_id,
                            extra={"request_id": request_id})
                return OverrideResult(False, "token is scoped to a different request")
            if row.override_used_at is not None:
                return OverrideResult(False, "token already used")
            exp = _aware(row.override_expires_at)
            if exp is None or exp < _now():
                return OverrideResult(False, "token expired")
            return OverrideResult(True, f"approved by human review {row.id}")

    def consume(self, token: str | None) -> None:
        """Mark single-use. Called by the pipeline only when the override
        actually lifted something, so a token presented on a request that
        was not blocked is not wasted."""
        if not token:
            return
        with session_scope() as s:
            row = s.execute(
                select(ReviewRequest).where(ReviewRequest.override_token_hash == token_hash(token))
            ).scalar_one_or_none()
            if row is not None and row.override_used_at is None:
                row.override_used_at = _now()
