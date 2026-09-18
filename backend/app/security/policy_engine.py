"""Policy engine: maps findings to actions.

This module contains no detection logic. It never looks at prompt text. It
receives what the scanners found -- typed, scored, located -- and answers
one question per finding: allow, warn, sanitise, or block? Then it folds
those into one decision for the request.

The rules live in config/policies.yaml and are hot-reloaded when the file
changes. A tenant can move from "sanitise PII" to "block PII" without a
deploy, and the audit log records which policy version was in force.

Separation of concerns is the point. The secret scanner must not know that
AWS keys are blocked; the policy file must not know how AWS keys are
recognised. Either can change without the other.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.config import settings
from app.contracts.common import (
    BlockReason,
    Decision,
    Detection,
    DetectionCategory,
    EntropyFinding,
    InjectionFinding,
    PolicyAction,
)
from app.utils.logging import get_logger

log = get_logger(__name__)

# Precedence when folding per-finding actions into one request decision.
_RANK: dict[PolicyAction, int] = {
    PolicyAction.ALLOW: 0,
    PolicyAction.WARN: 1,
    PolicyAction.SANITIZE: 2,
    PolicyAction.BLOCK: 3,
}
_DECISION_FOR: dict[PolicyAction, Decision] = {
    PolicyAction.ALLOW: Decision.ALLOW,
    PolicyAction.WARN: Decision.WARN,
    PolicyAction.SANITIZE: Decision.SANITIZE,
    PolicyAction.BLOCK: Decision.BLOCK,
}


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    key: str
    action: PolicyAction
    appealable: bool = True
    code: str = "POLICY_BLOCK"
    http_status: int = 400
    priority: int = 0
    threshold: float | None = None
    note: str = ""


@dataclass
class Profile:
    name: str
    description: str
    rules: dict[str, Rule]

    def resolve(self, key: str) -> Rule | None:
        """Most specific key first: `pii.IN_AADHAAR` -> `pii` -> None."""
        while True:
            if key in self.rules:
                return self.rules[key]
            if "." not in key:
                return None
            key = key.rsplit(".", 1)[0]


@dataclass
class PolicySet:
    version: int
    default_profile: str
    profiles: dict[str, Profile]
    loaded_at: float
    source_mtime: float


def _merge_rule(base: Rule | None, raw: dict[str, Any], key: str) -> Rule:
    """Overlay `raw` on `base` (from an extended profile), field by field."""
    b = base or Rule(key=key, action=PolicyAction.ALLOW)
    return Rule(
        key=key,
        action=PolicyAction(str(raw.get("action", b.action.value)).lower()),
        appealable=bool(raw.get("appealable", b.appealable)),
        code=str(raw.get("code", b.code)),
        http_status=int(raw.get("http_status", b.http_status)),
        priority=int(raw.get("priority", b.priority)),
        threshold=(
            float(raw["threshold"]) if raw.get("threshold") is not None else b.threshold
        ),
        note=str(raw.get("note", b.note) or "").strip(),
    )


def load_policies(path: Path) -> PolicySet:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw_profiles: dict[str, dict] = raw.get("profiles") or {}
    built: dict[str, Profile] = {}

    def build(name: str, stack: tuple[str, ...] = ()) -> Profile:
        if name in built:
            return built[name]
        if name in stack:
            raise ValueError(f"policy profile cycle: {' -> '.join(stack + (name,))}")
        spec = raw_profiles.get(name)
        if spec is None:
            raise ValueError(f"policy profile '{name}' not found")
        parent = build(spec["extends"], stack + (name,)) if spec.get("extends") else None
        rules: dict[str, Rule] = dict(parent.rules) if parent else {}
        for key, rule_raw in (spec.get("rules") or {}).items():
            rules[key] = _merge_rule(rules.get(key), rule_raw or {}, key)
        prof = Profile(name=name, description=str(spec.get("description", "")).strip(), rules=rules)
        built[name] = prof
        return prof

    for name in raw_profiles:
        build(name)

    default = str(raw.get("default_profile", "default"))
    if default not in built:
        raise ValueError(f"default_profile '{default}' is not a defined profile")

    return PolicySet(
        version=int(raw.get("version", 1)),
        default_profile=default,
        profiles=built,
        loaded_at=time.time(),
        source_mtime=os.path.getmtime(path),
    )


# ---------------------------------------------------------------------------
# Inputs and outputs
# ---------------------------------------------------------------------------


@dataclass
class DecisionEvent:
    """One row of evidence: which rule applied to which finding."""

    key: str
    rule_key: str  # the rule that actually matched after fallback
    action: PolicyAction
    finding_type: str
    confidence: float
    message_index: int | None = None


@dataclass
class PolicyDecision:
    decision: Decision
    block_reason: BlockReason | None
    detections: list[Detection]  # same objects, `action` now set
    rules_fired: list[str]
    events: list[DecisionEvent]
    profile: str
    policy_version: int
    override_applied: bool
    override_refused: bool
    explanation: str
    duration_ms: float = 0.0
    counts: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or settings.policies_path
        self._lock = threading.Lock()
        self._set = load_policies(self.path)
        self._secret_categories: dict[str, str] | None = None

    # -- hot reload -----------------------------------------------------------

    def _maybe_reload(self) -> None:
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return
        if mtime == self._set.source_mtime:
            return
        with self._lock:
            if mtime == self._set.source_mtime:
                return
            try:
                self._set = load_policies(self.path)
                log.info("policies reloaded (v%d, %d profiles)", self._set.version,
                         len(self._set.profiles))
            except Exception as exc:  # noqa: BLE001 - keep serving the old set
                log.error("policy reload failed, keeping v%d: %s", self._set.version, exc)

    def force_reload(self) -> None:
        """Reload now. Used after a versioned write so the new rules are in
        force immediately, not on the next mtime check (which can lag by a
        second on coarse filesystems)."""
        with self._lock:
            self._set = load_policies(self.path)
            self._secret_categories = None
        log.info("policies reloaded on request (v%d)", self._set.version)

    @property
    def policies(self) -> PolicySet:
        self._maybe_reload()
        return self._set

    def profile(self, name: str | None = None) -> Profile:
        ps = self.policies
        n = name or settings.policy_profile or ps.default_profile
        prof = ps.profiles.get(n)
        if prof is None:
            log.warning("unknown policy profile %r, using %r", n, ps.default_profile)
            prof = ps.profiles[ps.default_profile]
        return prof

    # -- key derivation (mapping, not detection) --------------------------------

    def _secret_category(self, pattern_id: str | None) -> str | None:
        """Scanner rule id -> policy category, read from the pattern config."""
        if self._secret_categories is None:
            from app.security.secret_scanner import get_scanner  # noqa: WPS433

            self._secret_categories = {p.id: p.category for p in get_scanner().patterns}
        return self._secret_categories.get(pattern_id or "")

    def key_for(self, d: Detection) -> str:
        if d.category is DetectionCategory.SECRET:
            cat = self._secret_category(d.pattern)
            return f"secrets.{cat}" if cat else "secrets"
        if d.category is DetectionCategory.PII:
            return f"pii.{d.type}"
        return d.category.value.lower()

    # -- evaluation -----------------------------------------------------------

    def is_appealable(self, key: str, profile: str | None = None) -> bool:
        """Used by the review API. Unknown keys default to appealable: more
        oversight, not less, is the safe direction."""
        rule = self.profile(profile).resolve(_normalise_key(key))
        return True if rule is None else rule.appealable

    def evaluate(
        self,
        detections: list[Detection],
        entropy: list[EntropyFinding],
        injection: InjectionFinding,
        *,
        profile: str | None = None,
        override: bool = False,
        injection_summary: str | None = None,
    ) -> PolicyDecision:
        t0 = time.perf_counter()
        prof = self.profile(profile)
        events: list[DecisionEvent] = []
        actioned: list[Detection] = []
        blocking: list[tuple[Rule, str]] = []  # (rule, finding description)
        rules_fired: list[str] = []

        def record(key: str, rule: Rule | None, ftype: str, conf: float, mi: int | None) -> PolicyAction:
            action = rule.action if rule else PolicyAction.ALLOW
            rk = rule.key if rule else "(no rule: allow)"
            events.append(DecisionEvent(key, rk, action, ftype, conf, mi))
            if rule and rk not in rules_fired:
                rules_fired.append(rk)
            return action

        # Detections (secrets + PII)
        for d in detections:
            key = self.key_for(d)
            rule = prof.resolve(key)
            action = record(key, rule, d.type, d.confidence, d.message_index)
            actioned.append(d.model_copy(update={"action": action}))
            if action is PolicyAction.BLOCK and rule:
                blocking.append((rule, d.type))

        # Entropy warnings
        for e in entropy:
            rule = prof.resolve("high_entropy_strings")
            action = record("high_entropy_strings", rule, e.type, e.confidence, e.message_index)
            # Entropy can never block, whatever the file says. Spec s11.
            if action is PolicyAction.BLOCK:
                log.warning("policy: high_entropy_strings cannot block; treating as warn")
                events[-1].action = PolicyAction.WARN

        # Injection
        inj_rule = prof.resolve("prompt_injection")
        inj_threshold = (
            inj_rule.threshold if inj_rule and inj_rule.threshold is not None
            else settings.injection_threshold
        )
        injection_fires = injection.score >= inj_threshold
        if injection_fires and inj_rule:
            action = record("prompt_injection", inj_rule, "PROMPT_INJECTION",
                            injection.score, None)
            if action is PolicyAction.BLOCK:
                blocking.append((inj_rule, "PROMPT_INJECTION"))
        elif injection.matched_rules:
            # Below threshold: recorded as evidence, no action taken.
            events.append(DecisionEvent("prompt_injection", "(below threshold)",
                                        PolicyAction.ALLOW, "PROMPT_INJECTION",
                                        injection.score, None))

        # Fold
        top = max(
            (ev.action for ev in events), key=lambda a: _RANK[a], default=PolicyAction.ALLOW
        )
        override_applied = override_refused = False
        block_reason: BlockReason | None = None

        if top is PolicyAction.BLOCK:
            rule, _ = max(blocking, key=lambda rb: rb[0].priority)
            if override:
                # An override lifts only the APPEALABLE blocking rules. Any
                # non-appealable block -- a leaked credential -- survives it,
                # whatever else was in the request.
                lifted = [rb for rb in blocking if rb[0].appealable]
                remaining = [rb for rb in blocking if not rb[0].appealable]
                override_applied = bool(lifted)
                if remaining:
                    override_refused = True
                    rule, _ = max(remaining, key=lambda rb: rb[0].priority)
                else:
                    # Everything blocking was lifted. Proceed at the next-
                    # highest action; a lifted detection is still redacted.
                    non_block = [ev.action for ev in events if ev.action is not PolicyAction.BLOCK]
                    top = max(non_block, key=lambda a: _RANK[a], default=PolicyAction.ALLOW)
                    if any(d.action is PolicyAction.BLOCK for d in actioned):
                        top = max(top, PolicyAction.SANITIZE, key=lambda a: _RANK[a])
            if top is PolicyAction.BLOCK:
                block_reason = BlockReason(
                    code=rule.code,
                    message=_block_message(rule),
                    http_status=rule.http_status,
                    rule_id=rule.key,
                    appealable=rule.appealable,
                )

        # Any detection whose own action was BLOCK but the request was lifted
        # is downgraded to SANITIZE so it is still redacted.
        if override_applied and top is not PolicyAction.BLOCK:
            actioned = [
                d.model_copy(update={"action": PolicyAction.SANITIZE})
                if d.action is PolicyAction.BLOCK else d
                for d in actioned
            ]

        decision = _DECISION_FOR[top]
        counts = {
            "pii": sum(1 for d in actioned if d.category is DetectionCategory.PII),
            "secrets": sum(1 for d in actioned if d.category is DetectionCategory.SECRET),
            "entropy": len(entropy),
            "injection": 1 if injection_fires else 0,
        }
        explanation = _explain(decision, block_reason, actioned, entropy, injection,
                               injection_fires, override_applied, override_refused,
                               injection_summary)

        return PolicyDecision(
            decision=decision,
            block_reason=block_reason,
            detections=actioned,
            rules_fired=rules_fired,
            events=events,
            profile=prof.name,
            policy_version=self.policies.version,
            override_applied=override_applied,
            override_refused=override_refused,
            explanation=explanation,
            duration_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            counts=counts,
        )


# ---------------------------------------------------------------------------
# Wording (Requirement 4 -- transparency)
# ---------------------------------------------------------------------------


def _normalise_key(key: str) -> str:
    """Accept the forms the Gateway and older clients send."""
    if key.startswith("injection.") or key == "injection":
        return "prompt_injection"
    if key == "secrets.credentials":
        return "secrets"
    return key


def _block_message(rule: Rule) -> str:
    if rule.key == "prompt_injection":
        return "Prompt injection pattern detected. Request blocked by Aegis."
    if rule.key.startswith("secrets"):
        return "Sensitive credentials detected. Request blocked by Aegis."
    if rule.key.startswith("pii"):
        return "Personal data detected. Request blocked by Aegis policy."
    return "Request blocked by Aegis policy."


def _explain(
    decision: Decision,
    block_reason: BlockReason | None,
    detections: list[Detection],
    entropy: list[EntropyFinding],
    injection: InjectionFinding,
    injection_fires: bool,
    override_applied: bool,
    override_refused: bool,
    injection_summary: str | None,
) -> str:
    secrets = [d for d in detections if d.category is DetectionCategory.SECRET]
    pii = [d for d in detections if d.category is DetectionCategory.PII]
    parts: list[str] = []

    if decision is Decision.BLOCK and block_reason:
        if block_reason.rule_id == "prompt_injection":
            parts.append(injection_summary or (
                f"The prompt matched {len(injection.matched_rules)} injection rule(s); "
                f"score {injection.score:.2f}."
            ))
            parts.append("This is a heuristic decision; you can request human review.")
        elif block_reason.rule_id.startswith("secrets"):
            parts.append(
                f"{len(secrets)} credential(s) were detected in this prompt and it was not transmitted."
            )
            parts.append(
                "Credential blocks are not appealable; rotate the credential and resubmit without it."
                if not block_reason.appealable
                else "You can request human review of this decision."
            )
        else:
            kinds = sorted({d.type for d in pii})
            parts.append(
                f"{len(pii)} personal data item(s) ({', '.join(kinds)}) were detected and this "
                "policy profile blocks rather than sanitises them."
            )
            if block_reason.appealable:
                parts.append("You can request human review of this decision.")
        if override_refused:
            parts.append("An override token was presented but this block cannot be lifted.")
        return " ".join(parts)

    if override_applied:
        parts.append("A human reviewer approved an override; the original block was lifted.")
    if pii and decision in (Decision.SANITIZE, Decision.WARN):
        kinds = sorted({d.type for d in pii})
        verb = "were replaced with placeholders before transmission" if decision is Decision.SANITIZE \
            else "were flagged and allowed through under this policy profile"
        parts.append(f"{len(pii)} personal data item(s) ({', '.join(kinds)}) {verb}.")
    if secrets and decision is not Decision.BLOCK:
        parts.append(
            f"{len(secrets)} credential-shaped value(s) were "
            + ("replaced with placeholders." if decision is Decision.SANITIZE else "flagged.")
        )
    if entropy:
        parts.append(f"{len(entropy)} high-entropy string(s) flagged for review; not a block reason.")
    if injection.matched_rules and not injection_fires:
        parts.append(
            f"Injection heuristics matched at {injection.score:.2f}, below the block threshold."
        )
    if not parts:
        parts.append("No sensitive data or injection patterns detected.")
    return " ".join(parts)


@lru_cache
def get_policy_engine() -> PolicyEngine:
    return PolicyEngine()
