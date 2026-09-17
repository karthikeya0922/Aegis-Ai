"""Ingress and egress inspection endpoints.

Phase 0 delegates to app.stubs. Phase 7 and Phase 11 replace the bodies of
these handlers with the real pipeline; the request and response models do not
change, so Person 2's Gateway needs no edit.
"""

from __future__ import annotations

from fastapi import APIRouter, status

from app.contracts.egress import (
    EgressRequest,
    EgressResponse,
    VerifyRequest,
    VerifyResponse,
)
from app.contracts.inspect import InspectRequest, InspectResponse
from app.audit.service import record_inspection
from app.security.pipeline import get_pipeline
from app.stubs import stub_egress
from app.utils.logging import get_logger

router = APIRouter(tags=["inspection"])
log = get_logger(__name__)


@router.post(
    "/inspect",
    response_model=InspectResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect an outbound prompt and return a policy decision",
    description=(
        "Stateless. Returns ALLOW / SANITIZE / WARN / BLOCK plus the sanitized "
        "messages, the placeholder-to-original vault map, cache and routing "
        "hints, and measured per-stage timings.\n\n"
        "Always returns HTTP 200 -- a BLOCK is a *decision*, not a transport "
        "error. The Gateway is responsible for translating `block_reason."
        "http_status` into the status code the client sees."
    ),
)
async def inspect(req: InspectRequest) -> InspectResponse:
    # The pipeline logs its own summary line with the request id.
    result = get_pipeline().run(req)
    # The Inspector's half of the audit row. Fire-and-forget: a database
    # failure is counted and logged and never changes the response.
    record_inspection(req, result)
    return result


@router.post(
    "/inspect/egress",
    response_model=EgressResponse,
    summary="Screen a model response before it reaches the user",
    description=(
        "Runs harm and bias screening, and grounded verification when "
        "`reference_context` is supplied. Returns PASS / ANNOTATE / REPLACE."
    ),
)
async def inspect_egress(req: EgressRequest) -> EgressResponse:
    result = stub_egress(
        request_id=req.request_id,
        response_text=req.response_text,
        has_reference=bool(req.reference_context) and "grounding" in req.checks,
    )
    log.info(
        "egress request_id=%s action=%s grounding=%s",
        req.request_id,
        result.action.value,
        result.grounding.status.value,
        extra={"request_id": req.request_id},
    )
    return result


@router.post(
    "/verify",
    response_model=VerifyResponse,
    summary="Grounded Response Verification (standalone)",
    description=(
        "Compares an answer against a reference document using sentence-level "
        "claim extraction and NLI entailment. This is a heuristic support "
        "score, not a guarantee of factual correctness."
    ),
)
async def verify(req: VerifyRequest) -> VerifyResponse:
    egress = stub_egress(req.request_id, req.answer, has_reference=True)
    return VerifyResponse(
        request_id=req.request_id,
        grounding=egress.grounding,
        pipeline=egress.pipeline,
        total_duration_ms=egress.total_duration_ms,
    )
