"""Phase 0 stub responses.

Purpose: give Person 2 a real HTTP surface to build the Gateway against on day
one, before any model is loaded or any scanner is written.

These stubs are deliberately *keyword-reactive* rather than constant, so the
Gateway can exercise every branch it must handle -- BLOCK, SANITIZE, WARN,
ALLOW, cache-ineligible, and each routing complexity -- without waiting for
Phase 1-7.

Every function here is replaced by real logic in later phases. The contract
shape does not change when that happens. Nothing in this module is imported by
production code paths once Phase 7 lands; `STUB_MODE` in /api/health reports
whether a deployment is still serving stubs.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone

from app.contracts.audit import (
    AuditEventPage,
    AuditEventRecord,
    AuditReport,
    AuditReportSection,
)
from app.contracts.common import (
    BlockReason,
    Complexity,
    Decision,
    Detection,
    DetectionCategory,
    EntropyFinding,
    GroundingStatus,
    InjectionFinding,
    Message,
    PipelineStage,
    PolicyAction,
    ReviewStatus,
    StageStatus,
)
from app.contracts.egress import (
    BiasResult,
    EgressAction,
    EgressResponse,
    GroundingResult,
    SafetyResult,
)
from app.contracts.governance import (
    FairnessGroupResult,
    FairnessReportResponse,
    FairnessRun,
    PolicyResponse,
    ReviewListResponse,
    ReviewRecord,
)
from app.security.entropy import scan as entropy_scan
from app.security.injection import get_detector as get_injection_detector
from app.security.pii_scanner import get_pii_scanner
from app.security.redactor import get_redactor
from app.security.secret_scanner import get_scanner
from app.contracts.inspect import (
    CacheHint,
    DetectionBundle,
    DetectionCounts,
    InspectRequest,
    InspectResponse,
    RoutingHint,
    SemanticGuards,
    VaultPolicy,
)
from app.contracts.metrics import (
    CostStats,
    LatencyStats,
    MetricsResponse,
    ProviderMetricsResponse,
    ProviderStat,
    RuleCount,
    SecurityMetricsResponse,
    SustainabilityMetricsResponse,
    TokenStats,
)

STUB_MODE = True

def _now() -> datetime:
    return datetime.now(timezone.utc)


def stub_inspect(req: InspectRequest) -> InspectResponse:
    """Keyword-reactive ingress stub covering every branch the Gateway handles."""
    text = "\n".join(m.content for m in req.messages)

    pii: list[Detection] = []
    secrets: list[Detection] = []
    entropy: list[EntropyFinding] = []

    # Scanners run PER MESSAGE so every span carries a real message_index and
    # offsets into that message's own content. The redactor relies on this;
    # scanning the joined text (what earlier phases did) produced offsets
    # into a string that does not exist in the request.
    secret_ms = entropy_ms = pii_ms = 0.0
    for mi, m in enumerate(req.messages):
        # --- secrets (REAL as of Phase 1) ---------------------------------
        _t0 = time.perf_counter()
        sd, _ = get_scanner().scan(m.content, message_index=mi)
        secrets.extend(sd)
        secret_ms += time.perf_counter() - _t0

        # --- entropy (REAL as of Phase 1; warn-only by design) ------------
        _t0 = time.perf_counter()
        entropy.extend(entropy_scan(m.content, message_index=mi))
        entropy_ms += time.perf_counter() - _t0

        # --- PII (REAL as of Phase 2, India engine as of Phase 3) ---------
        _t0 = time.perf_counter()
        pd, _ = get_pii_scanner().scan(m.content, message_index=mi)
        pii.extend(pd)
        pii_ms += time.perf_counter() - _t0
    secret_ms = round(secret_ms * 1000.0, 3)
    entropy_ms = round(entropy_ms * 1000.0, 3)
    pii_ms = round(pii_ms * 1000.0, 3)

    # --- redaction (REAL as of Phase 5) -----------------------------------
    # Cross-scanner precedence, global placeholder numbering, offset-safe
    # splicing, and the vault map -- all in one place. The scanners' own
    # per-call vault maps are discarded; values are sliced from the source.
    _t0 = time.perf_counter()
    redaction = get_redactor().redact(req.messages, secrets + pii)
    secrets = [d for d in redaction.detections if d.category is DetectionCategory.SECRET]
    pii = [d for d in redaction.detections if d.category is DetectionCategory.PII]
    vault = redaction.vault
    redact_ms = round((time.perf_counter() - _t0) * 1000.0, 3)

    # --- injection (REAL as of Phase 4) -----------------------------------
    # Only user and tool turns are scanned. The operator's own system prompt
    # legitimately says things like "You are now a helpful assistant", and
    # assistant turns are the model's prior output, already inspected.
    _t0 = time.perf_counter()
    injection_text = "\n".join(m.content for m in req.messages if m.role in ("user", "tool"))
    detector = get_injection_detector()
    injection = detector.analyze(injection_text)
    injection_ms = round((time.perf_counter() - _t0) * 1000.0, 3)

    # --- decision ----------------------------------------------------------
    override_applied = bool(req.override_token)
    if injection.detected and not override_applied:
        decision = Decision.BLOCK
        block_reason = BlockReason(
            code="PROMPT_INJECTION_BLOCKED",
            message="Prompt injection pattern detected. Request blocked by Aegis.",
            http_status=403,
            rule_id=f"injection.{injection.matched_rules[0]}",
            appealable=True,
        )
        explanation = (
            detector.explain(injection)
            + " This is a heuristic decision; you can request human review."
        )
    elif secrets:
        decision = Decision.BLOCK
        block_reason = BlockReason(
            code="CREDENTIAL_LEAK_PREVENTED",
            message="Sensitive credentials detected. Request blocked by Aegis.",
            http_status=400,
            rule_id="secrets.credentials",
            appealable=False,
        )
        explanation = (
            f"{len(secrets)} credential(s) were detected in this prompt and it was "
            "not transmitted. Credential blocks are not appealable."
        )
    elif pii:
        decision = Decision.SANITIZE
        block_reason = None
        kinds = sorted({d.type for d in pii})
        explanation = (
            f"{len(pii)} personal data item(s) ({', '.join(kinds)}) were replaced "
            "with placeholders before transmission."
        )
    else:
        decision = Decision.ALLOW
        block_reason = None
        explanation = "No sensitive data or injection patterns detected."

    # --- routing hint ------------------------------------------------------
    words = len(text.split())
    if words < 20:
        complexity, reasons = Complexity.LOW, ["short_prompt"]
    elif words < 120:
        complexity, reasons = Complexity.MEDIUM, ["moderate_length"]
    else:
        complexity, reasons = Complexity.HIGH, ["long_prompt"]
    if re.search(r"(?i)\b(explain why|step by step|prove|derive|analyse|analyze)\b", text):
        complexity, reasons = Complexity.HIGH, reasons + ["reasoning_markers"]

    # --- cache hint --------------------------------------------------------
    cacheable = not secrets and not injection.detected
    cache = CacheHint(
        cacheable=cacheable,
        reason=None if cacheable else "sensitive_content",
        semantic_guards=SemanticGuards(
            negations=re.findall(r"(?i)\b(not|no|never|unsafe|cannot|without)\b", text),
            numbers=re.findall(r"\b\d+(?:\.\d+)?\b", text),
            entities=[],
        ),
    )

    pipeline = [
        PipelineStage(
            stage="pii_scanner",
            status=StageStatus.WARNING if pii else StageStatus.SUCCESS,
            duration_ms=pii_ms,
            detail=f"{len(pii)} finding(s)" if pii else None,
        ),
        PipelineStage(
            stage="secret_scanner",
            status=StageStatus.WARNING if secrets else StageStatus.SUCCESS,
            duration_ms=secret_ms,
            detail=f"{len(secrets)} finding(s)" if secrets else None,
        ),
        PipelineStage(
            stage="entropy_scanner",
            status=StageStatus.WARNING if entropy else StageStatus.SUCCESS,
            duration_ms=entropy_ms,
            detail=f"{len(entropy)} high-entropy string(s)" if entropy else None,
        ),
        PipelineStage(
            stage="injection_detector",
            status=(
                StageStatus.BLOCKED if injection.detected
                else StageStatus.WARNING if injection.matched_rules
                else StageStatus.SUCCESS
            ),
            duration_ms=injection_ms,
            detail=(
                f"score={injection.score} rules={','.join(injection.matched_rules[:3])}"
                if injection.matched_rules else None
            ),
        ),
        PipelineStage(
            stage="redactor",
            status=StageStatus.SUCCESS,
            duration_ms=redact_ms,
            detail=(
                f"{redaction.replacements} span(s) replaced across "
                f"{len(redaction.per_message)} message(s)"
                + (f", {redaction.dropped_overlaps} overlap(s) resolved" if redaction.dropped_overlaps else "")
            ) if redaction.replacements else None,
        ),
        PipelineStage(
            stage="policy_engine",
            status=StageStatus.BLOCKED
            if decision is Decision.BLOCK
            else StageStatus.SUCCESS,
            duration_ms=0.1,
            detail=f"decision={decision.value}",
        ),
    ]

    # A blocked request is returned unmodified -- nothing is transmitted, so
    # nothing needs sanitising, and the Gateway may need the original for a
    # human-review replay. Otherwise the redactor's output is the contract.
    out_messages = req.messages if decision is Decision.BLOCK else redaction.messages

    return InspectResponse(
        request_id=req.request_id,
        policy_version=1,
        decision=decision,
        block_reason=block_reason,
        messages=out_messages,
        detections=DetectionBundle(
            pii=pii, secrets=secrets, entropy=entropy, injection=injection
        ),
        counts=DetectionCounts(
            pii=len(pii),
            secrets=len(secrets),
            entropy=len(entropy),
            injection=1 if injection.detected else 0,
        ),
        vault=vault if req.options.return_vault else {},
        vault_policy=redaction.vault_policy,
        cache=cache,
        routing_hint=RoutingHint(complexity=complexity, reasons=reasons),
        explanation=explanation if req.options.return_explanation else "",
        override_applied=override_applied,
        pipeline=pipeline,
        total_duration_ms=sum(s.duration_ms for s in pipeline),
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


COST_BASIS = "provider list price from config/pricing.yaml; stub values in Phase 0"
SUSTAINABILITY_BASIS = (
    "estimated from per-token energy assumptions in config/sustainability.yaml "
    "and a configurable grid intensity factor; stub values in Phase 0"
)


def stub_metrics(window_hours: int) -> MetricsResponse:
    return MetricsResponse(
        window_hours=window_hours,
        total_requests=0,
        blocked_requests=0,
        sanitized_requests=0,
        latency=LatencyStats(),
        tokens=TokenStats(),
        cost=CostStats(basis=COST_BASIS),
    )


def stub_security_metrics(window_hours: int) -> SecurityMetricsResponse:
    return SecurityMetricsResponse(window_hours=window_hours, top_rules=[RuleCount(rule_id="stub", count=0)])


def stub_sustainability_metrics(window_hours: int) -> SustainabilityMetricsResponse:
    return SustainabilityMetricsResponse(window_hours=window_hours, basis=SUSTAINABILITY_BASIS)


def stub_provider_metrics(window_hours: int) -> ProviderMetricsResponse:
    return ProviderMetricsResponse(
        window_hours=window_hours,
        providers=[ProviderStat(provider="stub", requests=0)],
        failover_events=0,
    )


def stub_audit_page(limit: int, offset: int) -> AuditEventPage:
    return AuditEventPage(items=[], total=0, limit=limit, offset=offset)


def stub_audit_report(tenant_id: str) -> AuditReport:
    return AuditReport(
        generated_at=_now(),
        tenant_id=tenant_id,
        sections=[
            AuditReportSection(
                title="Automated decisions",
                requirement="EU HLEG 7 - Accountability",
                rows=[],
                note="Populated from the request_audit table in Phase 12.",
            )
        ],
        disclaimer=(
            "This report is transaction evidence generated by Aegis. It supports "
            "a deployer's own record-keeping and oversight processes. It is not a "
            "conformity assessment and does not itself establish legal compliance."
        ),
    )


def stub_policy() -> PolicyResponse:
    return PolicyResponse(
        version=1,
        profile="default",
        available_profiles=["default", "strict"],
        yaml_body="# Real policy YAML lands in Phase 6\nversion: 1\nprofiles: {}\n",
        updated_at=_now(),
    )


def stub_reviews() -> ReviewListResponse:
    return ReviewListResponse(items=[], total=0)


def stub_review_record(request_id: str, justification: str) -> ReviewRecord:
    return ReviewRecord(
        id="rev_stub000000",
        request_id=request_id,
        tenant_id="default",
        created_at=_now(),
        original_decision=Decision.BLOCK,
        rule_fired="injection.instruction_override",
        user_justification=justification,
        status=ReviewStatus.PENDING,
        reviewer_note=None,
        decided_at=None,
        override_expires_at=_now() + timedelta(minutes=15),
    )


def stub_fairness_report() -> FairnessReportResponse:
    """Empty scaffold. Phase 13 fills this with *measured* numbers.

    Deliberately not populated with plausible-looking fake values: a fairness
    claim we have not measured is exactly the kind of thing this project
    exists to prevent.
    """
    return FairnessReportResponse(
        detector="pii.person",
        baseline=None,
        current=None,
        gap_closed=None,
        method=(
            "Recall of the PERSON recogniser over a fixed synthetic corpus of "
            "names across origin groups, embedded in identical sentence "
            "templates. Populated in Phase 13."
        ),
    )


__all__ = [
    "STUB_MODE",
    "FairnessGroupResult",
    "FairnessRun",
    "stub_audit_page",
    "stub_audit_report",
    "stub_egress",
    "stub_fairness_report",
    "stub_inspect",
    "stub_metrics",
    "stub_policy",
    "stub_provider_metrics",
    "stub_review_record",
    "stub_reviews",
    "stub_security_metrics",
    "stub_sustainability_metrics",
]
