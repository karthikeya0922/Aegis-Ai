"""The egress pipeline: screen the model's response before the user sees it.

    response -> harm screen -> bias screen -> grounding (if a reference was
    supplied) -> policy -> PASS | ANNOTATE | REPLACE

Every stage runs inside a StageRecorder block so its duration is measured.
The screens and the verifier report; config/policies.yaml decides, through
PolicyEngine.evaluate_egress, so a tenant can change "replace" to
"annotate" without touching code.

Streaming note for the Gateway: a REPLACE cannot retract tokens already
sent. When a reference document is attached the Gateway should buffer the
response and call this before emitting; otherwise it may stream and call
this afterwards for annotation only. That trade-off is the Gateway's to
make and is documented in the spec (s3).
"""

from __future__ import annotations

from app.contracts.common import GroundingStatus
from app.contracts.egress import EgressRequest, EgressResponse, GroundingResult
from app.security.policy_engine import get_policy_engine
from app.utils.logging import get_logger
from app.utils.timing import StageRecorder
from app.verification.grounding import get_verifier
from app.verification.screens import fallback_text, screen_bias, screen_harm

log = get_logger(__name__)


def run_egress(req: EgressRequest) -> EgressResponse:
    rec = StageRecorder()
    checks = set(req.checks)

    with rec.stage("harm_screen") as st:
        if "harm" in checks:
            safety = screen_harm(req.response_text)
            if safety.flagged:
                st.warn(f"score={safety.score} categories={','.join(safety.categories)}")
            elif safety.score > 0:
                st.note(f"score={safety.score} below threshold")
        else:
            from app.contracts.egress import SafetyResult

            safety = SafetyResult()
            st.note("not requested")

    with rec.stage("bias_screen") as st:
        if "bias" in checks:
            bias = screen_bias(req.response_text)
            if bias.flagged:
                st.warn(f"score={bias.score} signals={','.join(bias.signals)}")
            elif bias.score > 0:
                st.note(f"score={bias.score} below threshold")
        else:
            from app.contracts.egress import BiasResult

            bias = BiasResult()
            st.note("not requested")

    with rec.stage("grounding") as st:
        if "grounding" in checks and req.reference_context:
            outcome = get_verifier().verify(req.response_text, req.reference_context)
            grounding = outcome.result
            if not grounding.enabled:
                st.warn(f"skipped: {outcome.engine}")
            elif grounding.status is GroundingStatus.SKIPPED:
                st.note(f"skipped: {outcome.engine}")
            else:
                st.note(
                    f"score={grounding.score} {grounding.supported}/{grounding.claims} supported, "
                    f"{grounding.contradicted} contradicted"
                )
                if grounding.status is not GroundingStatus.GROUNDED:
                    st.warn(st.detail or "")
        else:
            grounding = GroundingResult(enabled=False, status=GroundingStatus.SKIPPED)
            st.note("no reference context" if "grounding" in checks else "not requested")

    with rec.stage("policy_engine") as st:
        decision = get_policy_engine().evaluate_egress(
            harm_flagged=safety.flagged,
            harm_categories=list(safety.categories),
            bias_flagged=bias.flagged,
            bias_signals=list(bias.signals),
            grounding_enabled=grounding.enabled and grounding.status is not GroundingStatus.SKIPPED,
            grounding_score=grounding.score,
            profile=req.policy_profile,
        )
        if decision.grounding_status is not None and grounding.enabled:
            # The profile's own bands take precedence over the verifier's default bands.
            grounding = grounding.model_copy(update={"status": decision.grounding_status})
        detail = f"profile={decision.profile} v{decision.policy_version} action={decision.action.value}"
        if decision.rules_fired:
            detail += f" rules={','.join(decision.rules_fired)}"
        if decision.action.value == "REPLACE":
            st.block(detail)
        elif decision.action.value == "ANNOTATE":
            st.warn(detail)
        else:
            st.note(detail)

    replacement = fallback_text(decision.replace_with) if decision.replace_with else None
    explanation = _explain(decision.action.value, decision.reasons, grounding, safety.flagged, bias.flagged)

    log.info(
        "egress request_id=%s action=%s harm=%s bias=%s grounding=%s total_ms=%.1f",
        req.request_id, decision.action.value, safety.flagged, bias.flagged,
        grounding.status.value, rec.total_ms, extra={"request_id": req.request_id},
    )

    return EgressResponse(
        request_id=req.request_id,
        safety=safety,
        bias=bias,
        grounding=grounding,
        action=decision.action,
        replacement_text=replacement,
        explanation=explanation,
        pipeline=rec.stages,
        total_duration_ms=rec.total_ms,
    )


def _explain(action: str, reasons: list[str], grounding: GroundingResult, harm: bool, bias: bool) -> str:
    parts: list[str] = []
    if action == "REPLACE":
        parts.append("The response was withheld and replaced with a fallback.")
    elif action == "ANNOTATE":
        parts.append("The response is allowed through with findings attached for review.")
    parts.extend(r[0].upper() + r[1:] + "." for r in reasons)
    if grounding.enabled and grounding.status is not GroundingStatus.SKIPPED:
        parts.append(
            f"Grounded Response Verification: {grounding.supported} of {grounding.claims} claim(s) "
            f"supported by the reference"
            + (f", {grounding.contradicted} contradicted" if grounding.contradicted else "")
            + ". This is a support score, not a guarantee of correctness."
        )
    elif grounding.enabled is False and not harm and not bias and not reasons:
        parts.append("No harmful or biased content signals detected.")
    if not parts:
        parts.append("No harmful or biased content signals detected.")
    return " ".join(parts)
