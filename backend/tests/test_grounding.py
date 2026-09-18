"""Phase 10 -- Grounded Response Verification.

Engine-aware: claim splitting and the no-reference / degraded paths run
everywhere; the NLI verdicts run only with the model and are skipped, not
failed, without it.
"""

from __future__ import annotations

import pytest

from app.contracts.common import GroundingStatus
from app.verification import grounding as mod
from app.verification.grounding import GroundingVerifier, get_verifier, split_claims, split_reference

REF = (
    "The data retention policy took effect on 1 March 2021. Audit rows are kept for 30 days "
    "by default. Personal identifiers are stored as salted hashes. The service runs on port 8000. "
    "Override tokens expire after 15 minutes."
)


@pytest.fixture(scope="module")
def ver() -> GroundingVerifier:
    v = get_verifier()
    v.warm()
    return v


needs_model = pytest.mark.skipif(get_verifier().degraded, reason="NLI model unavailable")


# ---------------------------------------------------------------------------
# Claim splitting
# ---------------------------------------------------------------------------


def test_split_claims_drops_questions_and_fragments():
    text = "The policy took effect in 2021. Really? Yes indeed. Audit rows are kept for thirty days."
    assert split_claims(text) == ["The policy took effect in 2021.", "Audit rows are kept for thirty days."]


def test_split_claims_caps_count():
    text = " ".join(f"Claim number {i} is asserted here." for i in range(100))
    assert len(split_claims(text)) == mod._MAX_CLAIMS


def test_split_reference_keeps_everything():
    assert len(split_reference(REF)) == 5


def test_known_limitation_abbreviations_split_badly():
    """'Dr. Smith' splits at the abbreviation. Documented, not hidden."""
    claims = split_claims("Dr. Smith approved the change. It shipped on Monday morning.")
    assert claims[0] != "Dr. Smith approved the change."


# ---------------------------------------------------------------------------
# Paths that need no model
# ---------------------------------------------------------------------------


def test_no_claims_is_skipped(ver):
    out = ver.verify("Really? Why?", REF)
    assert out.result.status is GroundingStatus.SKIPPED and out.result.claims == 0


def test_empty_reference_is_skipped(ver):
    out = ver.verify("The policy took effect in 2021.", "   ")
    assert out.result.status is GroundingStatus.SKIPPED


def test_degraded_is_reported_never_faked(monkeypatch):
    import builtins

    real = builtins.__import__

    def no_st(name, *a, **k):
        if name.startswith("sentence_transformers"):
            raise ImportError("sentence_transformers", name="sentence_transformers")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_st)
    v = GroundingVerifier()
    out = v.verify("The policy took effect in 2021.", REF)
    assert v.degraded and "not installed" in (v.degraded_reason or "")
    assert out.result.enabled is False and out.result.status is GroundingStatus.SKIPPED
    assert out.result.score is None, "no lexical fallback score -- that would be a fake number"
    assert "unavailable" in out.engine


# ---------------------------------------------------------------------------
# NLI verdicts
# ---------------------------------------------------------------------------


@needs_model
def test_labels_are_read_from_the_model(ver):
    assert set(ver.health()["labels"]) == {"entailment", "contradiction", "neutral"}


@needs_model
def test_supported_paraphrase(ver):
    out = ver.verify("User identifiers are hashed before storage.", REF)
    assert [s.verdict for s in out.claim_scores] == ["SUPPORTED"]
    assert out.result.score == 1.0 and out.result.status is GroundingStatus.GROUNDED


@needs_model
def test_contradiction_is_not_unsupported(ver):
    """A changed fact is CONTRADICTED; a fact the reference does not cover is
    UNSUPPORTED. The two are different failure modes and are kept apart."""
    out = ver.verify("The policy took effect in 2019. The service is written in Rust.", REF)
    verdicts = {s.claim[:20]: s.verdict for s in out.claim_scores}
    assert verdicts["The policy took effe"] == "CONTRADICTED"
    assert verdicts["The service is writt"] == "UNSUPPORTED"
    assert out.result.contradicted == 1 and out.result.unsupported == 1


@needs_model
def test_number_words_and_dates_resolve(ver):
    out = ver.verify("Override tokens are valid for fifteen minutes. The policy started in March 2021.", REF)
    assert all(s.verdict == "SUPPORTED" for s in out.claim_scores)


@needs_model
def test_mixed_answer_scores_and_lists_unsupported(ver):
    ans = (
        "The retention policy took effect in 2021. Audit rows are kept for 30 days. "
        "The policy took effect in 2019. The service is written in Rust."
    )
    out = ver.verify(ans, REF)
    r = out.result
    assert r.claims == 4 and r.supported == 2 and r.score == 0.5
    assert set(r.unsupported_claims) == {"The policy took effect in 2019.", "The service is written in Rust."}
    assert r.status in (GroundingStatus.REVIEW, GroundingStatus.UNGROUNDED)
    assert all(c.evidence for c in r.claim_detail), "every verdict names its evidence"


@needs_model
def test_evidence_is_the_best_matching_sentence(ver):
    out = ver.verify("Audit rows are kept for 30 days.", REF)
    assert "30 days" in out.claim_scores[0].evidence


@needs_model
def test_thresholds_from_settings(ver, monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "grounding_review_below", 0.99)
    out = ver.verify("The retention policy took effect in 2021. The service is written in Rust.", REF)
    assert out.result.score == 0.5 and out.result.status is GroundingStatus.REVIEW
    monkeypatch.setattr(config.settings, "grounding_replace_below", 0.6)
    out = ver.verify("The retention policy took effect in 2021. The service is written in Rust.", REF)
    assert out.result.status is GroundingStatus.UNGROUNDED
