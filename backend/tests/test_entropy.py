"""Phase 1 -- Shannon entropy.

The load-bearing test in this file is `test_entropy_findings_never_block`.
Everything else is accuracy; that one is the ethical constraint.
"""

from __future__ import annotations

import math

import pytest

from app.contracts.common import PolicyAction
from app.security import entropy


# ---------------------------------------------------------------------------
# The maths
# ---------------------------------------------------------------------------


def test_uniform_string_has_zero_entropy():
    assert entropy.shannon_entropy("aaaaaaaa") == 0.0
    assert entropy.shannon_entropy("") == 0.0


def test_two_equally_likely_symbols_is_one_bit():
    assert entropy.shannon_entropy("abab") == pytest.approx(1.0)


def test_four_equally_likely_symbols_is_two_bits():
    assert entropy.shannon_entropy("abcd") == pytest.approx(2.0)


def test_entropy_matches_definition():
    """Independently recompute H(X) = -sum p log2 p."""
    text = "hello world"
    counts = {c: text.count(c) for c in set(text)}
    expected = -sum(
        (n / len(text)) * math.log2(n / len(text)) for n in counts.values()
    )
    assert entropy.shannon_entropy(text) == pytest.approx(expected)


def test_random_key_scores_higher_than_prose():
    key = entropy.shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    prose = entropy.shannon_entropy("the quick brown fox jumps over the lazy dog")
    assert key > prose


def test_character_classes():
    assert entropy.character_classes("abcdef") == 1
    assert entropy.character_classes("abcDEF") == 2
    assert entropy.character_classes("abcDEF123") == 3
    assert entropy.character_classes("abcDEF123!") == 4


def test_normalized_entropy_is_bounded():
    for s in ["a", "ab", "abcd", "wJalrXUtnFEMI/K7MDENG/bPxRfiCY", ""]:
        assert 0.0 <= entropy.normalized_entropy(s) <= 1.0


# ---------------------------------------------------------------------------
# False-positive corpus -- high entropy, not secrets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("token", "reason"),
    [
        ("550e8400-e29b-41d4-a716-446655440000", "uuid"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "git_sha"),
        ("a1b2c3d4e5", "short_hash"),
        ("#a3f2b1", "hex_color"),
        ("2024-03-15T10:30:00Z", "timestamp"),
        ("1234567890.12345", "numeric"),
        ("./src/components/Button.tsx", "path"),
        ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUg", "data_uri"),
        ("internationalization", "natural_language"),
    ],
)
def test_known_benign_tokens_are_recognised(token, reason):
    assert entropy.is_known_benign(token) == reason


def test_benign_tokens_produce_no_findings():
    text = (
        "commit da39a3ee5e6b4b0d3255bfef95601890afd80709 "
        "id 550e8400-e29b-41d4-a716-446655440000 "
        "at 2024-03-15T10:30:00Z in ./src/components/Button.tsx"
    )
    assert entropy.scan(text) == []


def test_prose_produces_no_findings():
    text = (
        "Please summarise the quarterly report and highlight the most "
        "significant changes in operating expenditure across each region."
    )
    assert entropy.scan(text) == []


# ---------------------------------------------------------------------------
# True positives
# ---------------------------------------------------------------------------


def test_high_entropy_token_is_flagged():
    findings = entropy.scan("the token is xQ9vB2mK7pL4nR8tW5yZ3aC6dF1gH0jS ok")
    assert len(findings) == 1
    assert findings[0].entropy >= 4.0
    assert findings[0].length == 32


def test_short_tokens_are_ignored():
    """Below the length floor there is not enough signal to judge."""
    assert entropy.scan("aB3$ xY7!") == []


def test_offsets_point_at_the_token():
    text = "prefix xQ9vB2mK7pL4nR8tW5yZ3aC6dF1gH0jS suffix"
    finding = entropy.scan(text)[0]
    assert text[finding.start : finding.end] == "xQ9vB2mK7pL4nR8tW5yZ3aC6dF1gH0jS"


def test_repeated_tokens_get_distinct_offsets():
    tok = "xQ9vB2mK7pL4nR8tW5yZ3aC6dF1gH0jS"
    findings = entropy.scan(f"{tok} and again {tok}")
    assert len(findings) == 2
    assert findings[0].start != findings[1].start


# ---------------------------------------------------------------------------
# The ethical constraint
# ---------------------------------------------------------------------------


def test_entropy_findings_never_block():
    """Entropy is a supporting signal. It may warn; it may never block.

    A high-entropy string is evidence that something *looks* random, which is
    not evidence that it is a credential. Blocking on it alone would deny
    users on a guess.
    """
    text = " ".join(
        [
            "xQ9vB2mK7pL4nR8tW5yZ3aC6dF1gH0jS",
            "pL4nR8tW5yZ3aC6dF1gH0jSxQ9vB2mK7",
            "F1gH0jSxQ9vB2mK7pL4nR8tW5yZ3aC6d",
        ]
    )
    findings = entropy.scan(text)
    assert findings, "expected findings for this corpus"
    for f in findings:
        assert f.action is PolicyAction.WARN


def test_confidence_is_capped_below_certainty():
    """Without a recognisable prefix the scanner is guessing, and says so."""
    findings = entropy.scan("Zx9Kq2Vm7Bn4Rt8Wy5Pl3Aj6Df1Gh0Sc" * 2)
    for f in findings:
        assert f.confidence <= 0.75


def test_confidence_modifier_is_bounded():
    """Entropy nudges a pattern match's confidence; it never dominates it."""
    for s in ["a", "aaaa", "abcd", "wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "x" * 100]:
        assert -0.10 <= entropy.entropy_confidence_modifier(s) <= 0.10


def test_threshold_is_configurable():
    text = "the token is xQ9vB2mK7pL4nR8tW5yZ3aC6dF1gH0jS ok"
    assert entropy.scan(text, threshold=99.0) == []
    assert entropy.scan(text, threshold=1.0)
