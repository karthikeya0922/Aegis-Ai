"""Contracts for the three governance surfaces:

  * policies   -- versioned, auditable rule configuration (Requirement 7)
  * reviews    -- human oversight of automated blocks (Requirement 1)
  * fairness   -- measured detector equity across populations (Requirement 5)
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.contracts.common import Decision, ReviewStatus, StrictModel

# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


class PolicyResponse(StrictModel):
    version: int
    profile: str
    available_profiles: list[str] = Field(default_factory=list)
    yaml_body: str
    updated_at: datetime | None = None


class PolicyUpdateRequest(StrictModel):
    yaml_body: str
    author_ref: str | None = None
    note: str | None = None


class PolicyRollbackRequest(StrictModel):
    author_ref: str | None = None
    note: str | None = None


class PolicyVersionSummary(StrictModel):
    version: int
    created_at: datetime
    diff_summary: str | None = None
    note: str | None = None


class PolicyHistoryResponse(StrictModel):
    versions: list[PolicyVersionSummary] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Human review  (Requirement 1 -- human agency and oversight)
# ---------------------------------------------------------------------------


class ReviewCreateRequest(StrictModel):
    request_id: str
    tenant_id: str = "default"
    user_ref: str | None = None
    original_decision: Decision
    rule_fired: str | None = None
    user_justification: str = Field(min_length=1, max_length=2000)


class ReviewRecord(StrictModel):
    id: str
    request_id: str
    tenant_id: str
    created_at: datetime
    original_decision: Decision
    rule_fired: str | None = None
    user_justification: str
    status: ReviewStatus
    reviewer_note: str | None = None
    decided_at: datetime | None = None
    override_expires_at: datetime | None = None


class ReviewCreateResponse(StrictModel):
    review: ReviewRecord
    accepted: bool
    reason: str | None = None


class ReviewListResponse(StrictModel):
    items: list[ReviewRecord] = Field(default_factory=list)
    total: int = 0


class ReviewDecisionRequest(StrictModel):
    approve: bool
    reviewer_ref: str | None = None
    reviewer_note: str | None = Field(default=None, max_length=2000)


class ReviewDecisionResponse(StrictModel):
    review: ReviewRecord
    override_token: str | None = None
    override_expires_at: datetime | None = None


# ---------------------------------------------------------------------------
# Fairness  (Requirement 5 -- diversity, non-discrimination and fairness)
# ---------------------------------------------------------------------------


class FairnessGroupResult(StrictModel):
    group: str
    sample_size: int
    detected: int
    recall: float = Field(ge=0.0, le=1.0)
    precision: float | None = Field(default=None, ge=0.0, le=1.0)
    f1: float | None = Field(default=None, ge=0.0, le=1.0)


class FairnessRun(StrictModel):
    run_id: str
    run_at: datetime
    label: str
    detector: str
    groups: list[FairnessGroupResult] = Field(default_factory=list)
    best_group_recall: float | None = None
    worst_group_recall: float | None = None
    recall_gap: float | None = None
    notes: str | None = None
    # Free-form measured breakdown, e.g. "indian.held_out.recall",
    # "indian.by_engine.presidio", "anglo.false_positives". Keys are stable
    # strings; the dashboard may render any subset.
    breakdown: dict[str, float] = Field(default_factory=dict)


class FairnessReportResponse(StrictModel):
    detector: str
    baseline: FairnessRun | None = None
    current: FairnessRun | None = None
    # baseline gap minus current gap. Zero when the worst-served group did
    # not change -- which is itself a finding, not a failure of the report.
    gap_closed: float | None = None
    # current recall minus baseline recall, per group, so a lift in one group
    # is visible even when the overall gap is set by a different group.
    deltas: dict[str, float] = Field(default_factory=dict)
    method: str
    disclaimer: str = (
        "Recall measured against a fixed synthetic name corpus, not a "
        "representative population sample. Indicative of relative detector "
        "behaviour across groups, not an absolute accuracy claim."
    )
