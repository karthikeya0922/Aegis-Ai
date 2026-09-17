"""The ingress inspection pipeline.

This is the real /inspect. It replaces the Phase 0 stub orchestration and
is the single place the scanners, redactor and policy engine are composed:

    for each message:  secrets -> entropy -> PII
    resolve overlaps across scanners
    injection (user and tool turns only)
    policy  (config/policies.yaml)
    redact  (only what policy said to sanitise)
    routing hint, cache hint
    -> InspectResponse

Every stage runs inside a StageRecorder block, so its duration is measured
by construction -- there is no code path that can emit an estimated or
hardcoded number. A stage that does not run is recorded as skipped rather
than omitted; the dashboard must be able to show *why* something did not
happen.

The pipeline is stateless. Session state -- the vault, the cache -- belongs
to the Gateway's Redis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol

import yaml

from app.config import settings
from app.contracts.common import (
    Complexity,
    Decision,
    Detection,
    DetectionCategory,
    EntropyFinding,
    Message,
    StageStatus,
)
from app.contracts.inspect import (
    CacheHint,
    DetectionBundle,
    DetectionCounts,
    InspectRequest,
    InspectResponse,
    RoutingHint,
    SemanticGuards,
)
from app.security.entropy import scan as entropy_scan
from app.security.injection import InjectionDetector, get_detector
from app.security.pii_scanner import PIIScanner, get_pii_scanner
from app.security.policy_engine import PolicyEngine, get_policy_engine
from app.security.redactor import Redactor, get_redactor
from app.security.secret_scanner import SecretScanner, get_scanner
from app.utils.logging import get_logger
from app.utils.timing import StageRecorder

log = get_logger(__name__)

# Roles whose content is scanned for injection. The operator's own system
# prompt legitimately says "You are now a helpful assistant"; assistant turns
# are the model's prior output, already inspected on the way out.
_INJECTION_ROLES = frozenset({"user", "tool"})


# ---------------------------------------------------------------------------
# Routing / cache configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RoutingConfig:
    version: int
    low_max_words: int
    medium_max_words: int
    reasoning_markers: tuple[str, ...]
    code_markers: tuple[str, ...]
    code_high_lines: int
    multi_question_threshold: int
    negations: tuple[str, ...]
    number_pattern: re.Pattern[str]
    max_entities: int
    allow_pii_default: bool


def load_routing_config(path: Path) -> RoutingConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    c = raw.get("complexity") or {}
    g = raw.get("semantic_guards") or {}
    cache = raw.get("cache") or {}
    return RoutingConfig(
        version=int(raw.get("version", 1)),
        low_max_words=int(c.get("low_max_words", 20)),
        medium_max_words=int(c.get("medium_max_words", 120)),
        reasoning_markers=tuple(str(m).lower() for m in c.get("reasoning_markers", [])),
        code_markers=tuple(str(m) for m in c.get("code_markers", [])),
        code_high_lines=int(c.get("code_high_lines", 30)),
        multi_question_threshold=int(c.get("multi_question_threshold", 3)),
        negations=tuple(str(n).lower() for n in g.get("negations", [])),
        number_pattern=re.compile(str(g.get("number_pattern", r"\b\d+(?:[.,]\d+)?%?\b"))),
        max_entities=int(g.get("max_entities", 8)),
        allow_pii_default=bool(cache.get("allow_pii_default", False)),
    )


# ---------------------------------------------------------------------------
# Override verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OverrideResult:
    valid: bool
    reason: str


class OverrideVerifier(Protocol):
    def verify(self, token: str | None, request_id: str) -> OverrideResult: ...


class PermissiveOverrideVerifier:
    """Phase 7 placeholder: any well-formed token is accepted.

    Phase 14 replaces this with a verifier that checks the token against the
    review_request table: single use, scoped to one request_id, unexpired.
    Listed in the debt ledger.
    """

    def verify(self, token: str | None, request_id: str) -> OverrideResult:
        if not token:
            return OverrideResult(False, "no token")
        if not token.startswith("ovr_"):
            return OverrideResult(False, "malformed token")
        return OverrideResult(True, "accepted (permissive verifier; Phase 14 adds real checks)")


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


_CAP_TOKEN = re.compile(r"\b[A-Z][a-z]{2,}\b")
_QUESTION = re.compile(r"\?")


class InspectionPipeline:
    def __init__(
        self,
        *,
        secrets: SecretScanner | None = None,
        pii: PIIScanner | None = None,
        injection: InjectionDetector | None = None,
        policy: PolicyEngine | None = None,
        redactor: Redactor | None = None,
        routing: RoutingConfig | None = None,
        override_verifier: OverrideVerifier | None = None,
    ) -> None:
        self.secrets = secrets or get_scanner()
        self.pii = pii or get_pii_scanner()
        self.injection = injection or get_detector()
        self.policy = policy or get_policy_engine()
        self.redactor = redactor or get_redactor()
        self.routing = routing or load_routing_config(settings.routing_path)
        self.override_verifier = override_verifier or PermissiveOverrideVerifier()

    # -- hints ------------------------------------------------------------------

    def classify_complexity(self, messages: list[Message]) -> RoutingHint:
        text = "\n".join(m.content for m in messages if m.role in _INJECTION_ROLES)
        lowered = text.lower()
        words = len(text.split())
        reasons: list[str] = []
        cfg = self.routing

        if words < cfg.low_max_words:
            level, reasons = Complexity.LOW, ["short_prompt"]
        elif words < cfg.medium_max_words:
            level, reasons = Complexity.MEDIUM, ["moderate_length"]
        else:
            level, reasons = Complexity.HIGH, ["long_prompt"]

        if any(m in lowered for m in cfg.reasoning_markers):
            level = Complexity.HIGH
            reasons.append("reasoning_markers")

        if any(m in text for m in cfg.code_markers):
            code_lines = sum(1 for ln in text.splitlines() if ln.strip())
            if code_lines > cfg.code_high_lines:
                level = Complexity.HIGH
                reasons.append("large_code_block")
            elif level is Complexity.LOW:
                level = Complexity.MEDIUM
                reasons.append("code_present")
            else:
                reasons.append("code_present")

        if len(_QUESTION.findall(text)) >= cfg.multi_question_threshold and level is not Complexity.HIGH:
            level = Complexity.MEDIUM if level is Complexity.LOW else level
            reasons.append("multi_part_question")

        return RoutingHint(complexity=level, reasons=reasons)

    def cache_hint(
        self,
        messages: list[Message],
        decision: Decision,
        detections: list[Detection],
    ) -> CacheHint:
        has_secret = any(d.category is DetectionCategory.SECRET for d in detections)
        has_pii = any(d.category is DetectionCategory.PII for d in detections)
        allow_pii = settings.cache_allow_pii or self.routing.allow_pii_default

        if decision is Decision.BLOCK:
            return CacheHint(cacheable=False, reason="blocked")
        if has_secret:
            return CacheHint(cacheable=False, reason="credential_present")
        if has_pii and not allow_pii:
            return CacheHint(cacheable=False, reason="personal_data_present")

        # Guards are extracted from the ORIGINAL user text so that paraphrases
        # that flip a negation or change a number never share a cache entry.
        text = " ".join(m.content for m in messages if m.role in _INJECTION_ROLES)
        lowered = text.lower()
        negations = [n for n in self.routing.negations if re.search(rf"\b{re.escape(n)}\b", lowered)]
        numbers = self.routing.number_pattern.findall(text)

        # Capitalised tokens outside any detection span. With PII excluded
        # above this is safe; with allow_pii it still skips detected spans.
        covered = [(d.message_index, d.start, d.end) for d in detections]
        entities: list[str] = []
        for mi, m in enumerate(messages):
            if m.role not in _INJECTION_ROLES:
                continue
            for tok in _CAP_TOKEN.finditer(m.content):
                if any(c[0] == mi and c[1] <= tok.start() < c[2] for c in covered):
                    continue
                if tok.group(0) not in entities:
                    entities.append(tok.group(0))
                if len(entities) >= self.routing.max_entities:
                    break
        return CacheHint(
            cacheable=True,
            reason=("personal_data_allowed_by_config" if has_pii else None),
            semantic_guards=SemanticGuards(negations=negations, numbers=numbers, entities=entities),
        )

    # -- run --------------------------------------------------------------------

    def run(self, req: InspectRequest) -> InspectResponse:
        rec = StageRecorder()
        messages = req.messages

        secret_dets: list[Detection] = []
        pii_dets: list[Detection] = []
        entropy: list[EntropyFinding] = []

        with rec.stage("secret_scanner") as st:
            for mi, m in enumerate(messages):
                found, _ = self.secrets.scan(m.content, message_index=mi)
                secret_dets.extend(found)
            if secret_dets:
                st.warn(f"{len(secret_dets)} finding(s)")

        with rec.stage("entropy_scanner") as st:
            for mi, m in enumerate(messages):
                entropy.extend(entropy_scan(m.content, message_index=mi))
            if entropy:
                st.warn(f"{len(entropy)} high-entropy string(s)")

        with rec.stage("pii_scanner") as st:
            for mi, m in enumerate(messages):
                found, _ = self.pii.scan(m.content, message_index=mi)
                pii_dets.extend(found)
            if pii_dets:
                st.warn(f"{len(pii_dets)} finding(s)")
            if self.pii.degraded:
                st.note((st.detail + "; " if st.detail else "") + "degraded: regex-only")

        with rec.stage("overlap_resolution") as st:
            resolved, dropped = self.redactor.resolve(secret_dets + pii_dets)
            if dropped:
                st.note(f"{dropped} overlapping finding(s) resolved")

        with rec.stage("injection_detector") as st:
            inj_text = "\n".join(m.content for m in messages if m.role in _INJECTION_ROLES)
            injection = self.injection.analyze(inj_text)
            if injection.detected:
                st.block(f"score={injection.score} rules={','.join(injection.matched_rules[:3])}")
            elif injection.matched_rules:
                st.warn(f"score={injection.score} rules={','.join(injection.matched_rules[:3])}")

        with rec.stage("override_verification") as st:
            override = self.override_verifier.verify(req.override_token, req.request_id)
            if req.override_token:
                st.note(override.reason)
            else:
                st.note("no token presented")

        with rec.stage("policy_engine") as st:
            profile = req.policy_profile or (
                "strict" if (req.mode or "").lower() == "strict" else None
            )
            decision_result = self.policy.evaluate(
                resolved,
                entropy,
                injection,
                profile=profile,
                override=override.valid,
                injection_summary=(
                    self.injection.explain(injection) if injection.matched_rules else None
                ),
            )
            detail = (
                f"profile={decision_result.profile} v{decision_result.policy_version} "
                f"decision={decision_result.decision.value}"
            )
            if decision_result.rules_fired:
                detail += f" rules={','.join(decision_result.rules_fired)}"
            if decision_result.override_applied:
                detail += " override=applied"
            if decision_result.override_refused:
                detail += " override=refused"
            if decision_result.decision is Decision.BLOCK:
                st.block(detail)
            else:
                st.note(detail)

        with rec.stage("redactor") as st:
            redaction = self.redactor.redact(messages, decision_result.detections, resolve=False)
            redaction.dropped_overlaps = dropped
            if redaction.replacements:
                st.note(
                    f"{redaction.replacements} span(s) replaced across "
                    f"{len(redaction.per_message)} message(s)"
                )
            if redaction.skipped_invalid:
                st.warn(f"{redaction.skipped_invalid} finding(s) had invalid offsets and were dropped")

        with rec.stage("routing_hint") as st:
            routing_hint = self.classify_complexity(messages)
            st.note(f"{routing_hint.complexity.value}: {','.join(routing_hint.reasons)}")

        with rec.stage("cache_hint") as st:
            cache = self.cache_hint(messages, decision_result.decision, redaction.detections)
            if cache.cacheable:
                st.note(
                    f"cacheable; guards: {len(cache.semantic_guards.negations)} negation(s), "
                    f"{len(cache.semantic_guards.numbers)} number(s), "
                    f"{len(cache.semantic_guards.entities)} entity(ies)"
                )
            else:
                st.note(f"not cacheable: {cache.reason}")

        secrets_out = [d for d in redaction.detections if d.category is DetectionCategory.SECRET]
        pii_out = [d for d in redaction.detections if d.category is DetectionCategory.PII]

        # A blocked request is returned unmodified: nothing is transmitted,
        # and the Gateway may need the original for a human-review replay.
        out_messages = messages if decision_result.decision is Decision.BLOCK else redaction.messages

        log.info(
            "inspect request_id=%s decision=%s profile=%s pii=%d secrets=%d injection=%s total_ms=%.1f",
            req.request_id,
            decision_result.decision.value,
            decision_result.profile,
            len(pii_out),
            len(secrets_out),
            injection.detected,
            rec.total_ms,
            extra={"request_id": req.request_id},
        )

        return InspectResponse(
            request_id=req.request_id,
            policy_version=decision_result.policy_version,
            decision=decision_result.decision,
            block_reason=decision_result.block_reason,
            messages=out_messages,
            detections=DetectionBundle(
                pii=pii_out, secrets=secrets_out, entropy=entropy, injection=injection
            ),
            counts=DetectionCounts(**decision_result.counts),
            vault=redaction.vault if req.options.return_vault else {},
            vault_policy=redaction.vault_policy,
            cache=cache,
            routing_hint=routing_hint,
            explanation=decision_result.explanation if req.options.return_explanation else "",
            override_applied=decision_result.override_applied,
            pipeline=rec.stages,
            total_duration_ms=rec.total_ms,
        )

    def warm(self) -> None:
        """Run one representative request so every component is initialised."""
        self.run(
            InspectRequest(
                request_id="req_warmup",
                messages=[Message(role="user", content="Contact Alex Example at alex@example.com about 2 items.")],
            )
        )


@lru_cache
def get_pipeline() -> InspectionPipeline:
    return InspectionPipeline()
