"""Contract for POST /inspect/egress -- output screening and grounding."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.contracts.common import (
    EgressAction,
    GroundingStatus,
    PipelineStage,
    StrictModel,
)

CheckName = Literal["harm", "bias", "grounding"]


class EgressRequest(StrictModel):
    request_id: str
    tenant_id: str = "default"
    response_text: str
    reference_context: str | None = None
    checks: list[CheckName] = Field(default_factory=lambda: ["harm", "bias"])
    policy_profile: str | None = None


class SafetyResult(StrictModel):
    flagged: bool = False
    categories: list[str] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0.0, le=1.0)


class BiasResult(StrictModel):
    flagged: bool = False
    signals: list[str] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0.0, le=1.0)


class ClaimVerdict(StrictModel):
    claim: str
    verdict: Literal["SUPPORTED", "UNSUPPORTED", "CONTRADICTED"]
    score: float = Field(ge=0.0, le=1.0)
    evidence: str | None = None


class GroundingResult(StrictModel):
    enabled: bool = False
    claims: int = 0
    supported: int = 0
    unsupported: int = 0
    contradicted: int = 0
    score: float | None = None
    status: GroundingStatus = GroundingStatus.SKIPPED
    unsupported_claims: list[str] = Field(default_factory=list)
    claim_detail: list[ClaimVerdict] = Field(default_factory=list)


class EgressResponse(StrictModel):
    request_id: str
    safety: SafetyResult = Field(default_factory=SafetyResult)
    bias: BiasResult = Field(default_factory=BiasResult)
    grounding: GroundingResult = Field(default_factory=GroundingResult)

    action: EgressAction = EgressAction.PASS
    replacement_text: str | None = None
    explanation: str = ""

    pipeline: list[PipelineStage] = Field(default_factory=list)
    total_duration_ms: float = Field(default=0.0, ge=0)


class VerifyRequest(StrictModel):
    """Standalone grounding check -- POST /verify."""

    request_id: str
    answer: str
    reference_context: str


class VerifyResponse(StrictModel):
    request_id: str
    grounding: GroundingResult
    pipeline: list[PipelineStage] = Field(default_factory=list)
    total_duration_ms: float = Field(default=0.0, ge=0)
