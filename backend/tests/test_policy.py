"""Phase 6 -- policy engine.

The engine maps findings to actions and contains no detection logic. These
tests build findings by hand so the matrix is exhaustive and independent
of scanner behaviour; a final block runs the real scanners end to end.
"""

from __future__ import annotations

import textwrap
import time
from pathlib import Path

import pytest

from app.contracts.common import (
    Decision,
    Detection,
    DetectionCategory,
    EntropyFinding,
    InjectionFinding,
    PolicyAction,
)
from app.security.policy_engine import PolicyEngine, get_policy_engine, load_policies


# ---------------------------------------------------------------------------
# Finding builders
# ---------------------------------------------------------------------------


def secret(pattern: str, type_: str = "SECRET", conf: float = 0.95) -> Detection:
    return Detection(type=type_, category=DetectionCategory.SECRET, placeholder="[S_1]",
                     confidence=conf, start=0, end=5, pattern=pattern, action=PolicyAction.ALLOW)


def pii(type_: str, conf: float = 0.9) -> Detection:
    return Detection(type=type_, category=DetectionCategory.PII, placeholder="[P_1]",
                     confidence=conf, start=0, end=5, action=PolicyAction.ALLOW)


def ent(h: float = 4.8) -> EntropyFinding:
    return EntropyFinding(entropy=h, length=32, confidence=0.6, start=0, end=32)


def inj(score: float, rules: list[str] | None = None) -> InjectionFinding:
    return InjectionFinding(detected=score >= 0.75, score=score,
                            matched_rules=rules or (["override.ignore_previous"] if score else []))


NO_INJ = inj(0.0)


@pytest.fixture(scope="module")
def engine() -> PolicyEngine:
    return get_policy_engine()


# ---------------------------------------------------------------------------
# Loading and inheritance
# ---------------------------------------------------------------------------


def test_profiles_load(engine):
    ps = engine.policies
    assert ps.version >= 1
    assert {"default", "strict", "permissive"} <= set(ps.profiles)
    assert ps.default_profile == "default"


def test_strict_extends_default(engine):
    d, s = engine.profile("default"), engine.profile("strict")
    # inherited unchanged
    assert s.resolve("prompt_injection").code == d.resolve("prompt_injection").code
    # overridden
    assert d.resolve("pii").action is PolicyAction.SANITIZE
    assert s.resolve("pii").action is PolicyAction.BLOCK
    # partial override keeps the parent's other fields
    assert s.resolve("prompt_injection").threshold == 0.60
    assert s.resolve("prompt_injection").http_status == 403


def test_most_specific_key_wins(engine):
    p = engine.profile("default")
    assert p.resolve("secrets.generic_credentials").action is PolicyAction.SANITIZE
    assert p.resolve("secrets.aws_credentials").action is PolicyAction.BLOCK  # falls back to secrets
    assert p.resolve("secrets").action is PolicyAction.BLOCK
    assert p.resolve("pii.IN_AADHAAR").key == "pii.IN_AADHAAR"
    assert p.resolve("pii.EMAIL_ADDRESS").key == "pii"  # fallback
    assert p.resolve("nonexistent.key") is None


def test_unknown_profile_falls_back_to_default(engine):
    assert engine.profile("does-not-exist").name == "default"


def test_cycle_is_rejected(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text(textwrap.dedent("""
        version: 1
        default_profile: a
        profiles:
          a: {extends: b, rules: {}}
          b: {extends: a, rules: {}}
    """), encoding="utf-8")
    with pytest.raises(ValueError, match="cycle"):
        load_policies(f)


def test_bad_default_profile_is_rejected(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("version: 1\ndefault_profile: nope\nprofiles:\n  a: {rules: {}}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="default_profile"):
        load_policies(f)


# ---------------------------------------------------------------------------
# The decision matrix -- default profile
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("dets", "entropy", "injection", "expected"),
    [
        ([], [], NO_INJ, Decision.ALLOW),
        ([], [ent()], NO_INJ, Decision.WARN),
        ([pii("EMAIL_ADDRESS")], [], NO_INJ, Decision.SANITIZE),
        ([pii("EMAIL_ADDRESS")], [ent()], NO_INJ, Decision.SANITIZE),
        ([secret("aws_access_key")], [], NO_INJ, Decision.BLOCK),
        ([secret("generic_secret_assignment")], [], NO_INJ, Decision.SANITIZE),
        ([secret("jwt")], [], NO_INJ, Decision.BLOCK),
        ([], [], inj(0.9), Decision.BLOCK),
        ([], [], inj(0.6), Decision.ALLOW),  # below threshold: evidence only
        ([pii("PERSON")], [], inj(0.6), Decision.SANITIZE),
        ([pii("PERSON"), secret("aws_access_key")], [ent()], inj(0.9), Decision.BLOCK),
    ],
)
def test_default_matrix(engine, dets, entropy, injection, expected):
    assert engine.evaluate(dets, entropy, injection, profile="default").decision is expected


def test_precedence_block_over_sanitize_over_warn(engine):
    r = engine.evaluate([pii("PERSON"), secret("aws_access_key")], [ent()], NO_INJ)
    assert r.decision is Decision.BLOCK
    # every finding still got its own action
    by_type = {d.type: d.action for d in r.detections}
    assert by_type["PERSON"] is PolicyAction.SANITIZE
    assert by_type["SECRET"] is PolicyAction.BLOCK


# ---------------------------------------------------------------------------
# Block reason and priority
# ---------------------------------------------------------------------------


def test_block_reason_secrets(engine):
    r = engine.evaluate([secret("aws_access_key")], [], NO_INJ)
    assert r.block_reason.code == "CREDENTIAL_LEAK_PREVENTED"
    assert r.block_reason.http_status == 400
    assert r.block_reason.appealable is False
    assert r.block_reason.rule_id == "secrets"


def test_block_reason_injection(engine):
    r = engine.evaluate([], [], inj(0.9))
    assert r.block_reason.code == "PROMPT_INJECTION_BLOCKED"
    assert r.block_reason.http_status == 403
    assert r.block_reason.appealable is True
    assert r.block_reason.rule_id == "prompt_injection"


def test_highest_priority_rule_supplies_the_block_reason(engine):
    """Injection (priority 100) outranks secrets (90) for the reason shown."""
    r = engine.evaluate([secret("aws_access_key")], [], inj(0.9))
    assert r.block_reason.rule_id == "prompt_injection"
    assert set(r.rules_fired) == {"secrets", "prompt_injection"}


def test_jwt_block_is_appealable_but_aws_is_not(engine):
    assert engine.evaluate([secret("jwt")], [], NO_INJ).block_reason.appealable is True
    assert engine.evaluate([secret("aws_access_key")], [], NO_INJ).block_reason.appealable is False


# ---------------------------------------------------------------------------
# Profiles change outcomes without code changes
# ---------------------------------------------------------------------------


def test_strict_blocks_pii(engine):
    r = engine.evaluate([pii("EMAIL_ADDRESS")], [], NO_INJ, profile="strict")
    assert r.decision is Decision.BLOCK
    assert r.block_reason.code == "PII_BLOCKED"
    assert r.block_reason.appealable is True


def test_strict_aadhaar_is_not_appealable(engine):
    r = engine.evaluate([pii("IN_AADHAAR")], [], NO_INJ, profile="strict")
    assert r.block_reason.appealable is False
    assert r.block_reason.rule_id == "pii.IN_AADHAAR"


def test_strict_lowers_injection_threshold(engine):
    assert engine.evaluate([], [], inj(0.65), profile="default").decision is Decision.ALLOW
    assert engine.evaluate([], [], inj(0.65), profile="strict").decision is Decision.BLOCK


def test_permissive_never_blocks(engine):
    r = engine.evaluate([pii("PERSON"), secret("aws_access_key")], [ent()], inj(0.95),
                        profile="permissive")
    assert r.decision is Decision.WARN
    assert r.block_reason is None
    assert r.rules_fired  # still recorded


# ---------------------------------------------------------------------------
# Override (human review, Requirement 1)
# ---------------------------------------------------------------------------


def test_override_lifts_appealable_block(engine):
    r = engine.evaluate([pii("PERSON")], [], inj(0.9), override=True)
    assert r.decision is Decision.SANITIZE
    assert r.override_applied is True
    assert r.block_reason is None
    assert "override" in r.explanation.lower()


def test_override_refused_for_non_appealable(engine):
    r = engine.evaluate([secret("aws_access_key")], [], NO_INJ, override=True)
    assert r.decision is Decision.BLOCK
    assert r.override_refused is True
    assert r.override_applied is False
    assert "cannot be lifted" in r.explanation


def test_override_lifts_injection_but_not_a_credential_in_the_same_request(engine):
    """An override lifts only the appealable rules. The credential survives.

    Without the token, injection (priority 100) supplies the block reason.
    With it, injection is lifted, the non-appealable AWS block remains, and
    the reason now names the rule that could not be lifted.
    """
    r = engine.evaluate([secret("aws_access_key")], [], inj(0.9), override=True)
    assert r.decision is Decision.BLOCK
    assert r.override_applied is True     # the injection block was lifted
    assert r.override_refused is True     # but a credential block remained
    assert r.block_reason.rule_id == "secrets"
    assert r.block_reason.appealable is False


def test_override_without_a_block_is_a_no_op(engine):
    r = engine.evaluate([pii("PERSON")], [], NO_INJ, override=True)
    assert r.decision is Decision.SANITIZE
    assert r.override_applied is False


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


def test_entropy_can_never_block(tmp_path):
    """Even if the file says block, entropy is downgraded to warn (spec s11)."""
    f = tmp_path / "p.yaml"
    f.write_text(textwrap.dedent("""
        version: 1
        default_profile: d
        profiles:
          d:
            rules:
              high_entropy_strings: {action: block}
    """), encoding="utf-8")
    e = PolicyEngine(f)
    r = e.evaluate([], [ent()], NO_INJ)
    assert r.decision is Decision.WARN


def test_every_finding_yields_an_event(engine):
    r = engine.evaluate([pii("PERSON"), secret("jwt")], [ent(), ent()], inj(0.9))
    assert len(r.events) == 5
    assert all(ev.rule_key for ev in r.events)


def test_below_threshold_injection_is_recorded_as_evidence(engine):
    r = engine.evaluate([], [], inj(0.6))
    assert r.decision is Decision.ALLOW
    assert any(ev.finding_type == "PROMPT_INJECTION" and ev.action is PolicyAction.ALLOW
               for ev in r.events)
    assert "below the block threshold" in r.explanation


def test_engine_does_not_touch_text(engine):
    """No text parameter exists. Detection logic cannot leak in."""
    import inspect

    assert "text" not in inspect.signature(engine.evaluate).parameters


def test_every_decision_has_an_explanation(engine):
    for dets, e_, i_ in [([], [], NO_INJ), ([pii("PERSON")], [], NO_INJ),
                         ([secret("jwt")], [], NO_INJ), ([], [], inj(0.9)), ([], [ent()], NO_INJ)]:
        assert engine.evaluate(dets, e_, i_).explanation


def test_counts_and_version(engine):
    r = engine.evaluate([pii("PERSON"), secret("jwt")], [ent()], inj(0.9))
    assert r.counts == {"pii": 1, "secrets": 1, "entropy": 1, "injection": 1}
    assert r.policy_version == engine.policies.version
    assert r.duration_ms >= 0


# ---------------------------------------------------------------------------
# Appealability lookup (used by the review API)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("secrets", False),
        ("secrets.credentials", False),      # legacy form from the Gateway
        ("secrets.aws_credentials", False),
        ("secrets.tokens", True),
        ("prompt_injection", True),
        ("injection.override.ignore_previous", True),  # legacy form
        ("pii", True),
        ("totally.unknown", True),           # unknown -> appealable: more oversight
    ],
)
def test_is_appealable(engine, key, expected):
    assert engine.is_appealable(key) is expected


# ---------------------------------------------------------------------------
# Hot reload
# ---------------------------------------------------------------------------


def test_hot_reload_on_file_change(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("version: 1\ndefault_profile: d\nprofiles:\n  d:\n    rules:\n      pii: {action: sanitize}\n",
                 encoding="utf-8")
    e = PolicyEngine(f)
    assert e.evaluate([pii("PERSON")], [], NO_INJ).decision is Decision.SANITIZE

    time.sleep(0.05)
    f.write_text("version: 2\ndefault_profile: d\nprofiles:\n  d:\n    rules:\n      pii: {action: block, code: X}\n",
                 encoding="utf-8")
    # force a different mtime on filesystems with coarse timestamps
    import os
    os.utime(f, (time.time() + 5, time.time() + 5))
    r = e.evaluate([pii("PERSON")], [], NO_INJ)
    assert r.decision is Decision.BLOCK
    assert r.policy_version == 2


def test_bad_reload_keeps_old_policies(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("version: 1\ndefault_profile: d\nprofiles:\n  d:\n    rules:\n      pii: {action: sanitize}\n",
                 encoding="utf-8")
    e = PolicyEngine(f)
    import os
    f.write_text("this: is: not: valid: yaml: [", encoding="utf-8")
    os.utime(f, (time.time() + 5, time.time() + 5))
    assert e.evaluate([pii("PERSON")], [], NO_INJ).decision is Decision.SANITIZE
    assert e.policies.version == 1


# ---------------------------------------------------------------------------
# End to end through the real scanners
# ---------------------------------------------------------------------------


def test_end_to_end_keys_are_derived_from_scanner_config(engine):
    from app.security.secret_scanner import get_scanner

    dets, _ = get_scanner().scan("AKIAIOSFODNN7EXAMPLE and postgres://u:p@h/db")
    keys = {engine.key_for(d) for d in dets}
    assert keys == {"secrets.aws_credentials", "secrets.database_credentials"}
