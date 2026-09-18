"""Ingress and egress inspection endpoints.

Both real. /inspect runs security/pipeline.py; /inspect/egress and /verify
run verification/egress.py and verification/grounding.py. Each records
its outcome on the request's audit row, fire-and-forget.
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
from app.audit.service import record_egress, record_inspection
from app.security.pipeline import get_pipeline
from app.verification.egress import run_egress
from app.verification.grounding import get_verifier
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
        "Runs the harm and bias screens and, when `reference_context` is "
        "supplied and `grounding` is in `checks`, Grounded Response "
        "Verification. Returns PASS / ANNOTATE / REPLACE as decided by the "
        "policy profile's egress rules; on REPLACE, `replacement_text` holds "
        "the configured fallback.\n\n"
        "The screens are heuristic (pattern-based) and the verification is an "
        "NLI support score, not a guarantee. A REPLACE cannot retract tokens "
        "already streamed: buffer when a reference document is attached.\n\n"
        "The Inspector records the outcome on the request's audit row; the "
        "Gateway need not repeat it in POST /audit/events."
    ),
)
async def inspect_egress(req: EgressRequest) -> EgressResponse:
    result = run_egress(req)
    record_egress(req.request_id, result)
    return result


@router.post(
    "/verify",
    response_model=VerifyResponse,
    summary="Grounded Response Verification (standalone)",
    description=(
        "Compares an answer against a reference document: sentence-level "
        "claims, top-k evidence by embedding similarity, NLI cross-encoder "
        "entailment per claim. Returns SUPPORTED / UNSUPPORTED / CONTRADICTED "
        "per claim and a support score. This is a heuristic support score, "
        "not a guarantee of factual correctness, and it cannot judge whether "
        "the reference itself is true."
    ),
)
async def verify(req: VerifyRequest) -> VerifyResponse:
    from app.utils.timing import StageRecorder

    rec = StageRecorder()
    with rec.stage("grounding") as st:
        outcome = get_verifier().verify(req.answer, req.reference_context)
        g = outcome.result
        if not g.enabled:
            st.warn(f"skipped: {outcome.engine}")
        else:
            st.note(f"score={g.score} {g.supported}/{g.claims} supported, {g.contradicted} contradicted")
    return VerifyResponse(
        request_id=req.request_id, grounding=g, pipeline=rec.stages, total_duration_ms=rec.total_ms,
    )
