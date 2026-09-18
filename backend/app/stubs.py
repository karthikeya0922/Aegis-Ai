"""Stub responses for subsystems that have not shipped yet.

Phase 0 gave Person 2 a complete HTTP surface on day one by stubbing every
endpoint. Each phase since has replaced one stub with the real thing; this
module now holds only what remains:

    stub_egress            -> Phase 10 (grounding) and Phase 11 (harm/bias)

The ingress path -- /inspect -- is real as of Phase 7 (security/pipeline.py)
and nothing here is on it. /api/health reports per component which of the
above are still stubs.
"""

from __future__ import annotations

from app.contracts.common import (
    GroundingStatus,
    PipelineStage,
    StageStatus,
)
from app.contracts.egress import (
    BiasResult,
    EgressAction,
    EgressResponse,
    GroundingResult,
    SafetyResult,
)


def stub_egress(request_id: str, response_text: str, has_reference: bool) -> EgressResponse:
    grounding = (
        GroundingResult(
            enabled=True,
            claims=10,
            supported=8,
            unsupported=2,
            contradicted=0,
            score=0.80,
            status=GroundingStatus.REVIEW,
            unsupported_claims=["The policy took effect in 2019."],
        )
        if has_reference
        else GroundingResult(enabled=False, status=GroundingStatus.SKIPPED)
    )
    pipeline = [
        PipelineStage(stage="harm_screen", status=StageStatus.SUCCESS, duration_ms=0.3),
        PipelineStage(stage="bias_screen", status=StageStatus.SUCCESS, duration_ms=0.3),
        PipelineStage(
            stage="grounding",
            status=StageStatus.WARNING if has_reference else StageStatus.SKIPPED,
            duration_ms=0.5 if has_reference else 0.0,
        ),
    ]
    return EgressResponse(
        request_id=request_id,
        safety=SafetyResult(),
        bias=BiasResult(),
        grounding=grounding,
        action=EgressAction.ANNOTATE if has_reference else EgressAction.PASS,
        replacement_text=None,
        explanation=(
            "2 of 10 claims could not be matched to the supplied document."
            if has_reference
            else "No harmful or biased content signals detected."
        ),
        pipeline=pipeline,
        total_duration_ms=sum(s.duration_ms for s in pipeline),
    )


__all__ = ["stub_egress"]
