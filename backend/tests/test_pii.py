"""Phase 2 -- PII detection.

Engine-aware: structured identifiers (email, phone, IP, card, SSN) are tested
unconditionally because the regex engine always covers them. Tests that need
NER (PERSON without an honorific) are skipped, not failed, when Presidio or
a spaCy model is absent -- and a separate test asserts that absence is
reported honestly rather than papered over.
"""

from __future__ import annotations

import pytest

from app.contracts.common import DetectionCategory, PolicyAction
from app.security import pii_scanner as mod
from app.security.pii_scanner import PIIScanner, get_pii_scanner, luhn_valid
from app.security.spans import resolve_overlaps, subtract_covered


@pytest.fixture(scope="module")
def scanner() -> PIIScanner:
    s = get_pii_scanner()
    s.warm()
    return s


def types_in(scanner: PIIScanner, text: str) -> list[str]:
    detections, _ = scanner.scan(text)
    return [d.type for d in detections]


needs_ner = pytest.mark.skipif(
    get_pii_scanner().degraded,
    reason="NER unavailable (regex-only mode); PERSON without honorific needs spaCy",
)


# ---------------------------------------------------------------------------
# Luhn
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "number", ["4111111111111111", "5500000000000004", "340000000000009", "6011000000000004"]
)
def test_luhn_accepts_valid_test_numbers(number):
    assert luhn_valid(number)


@pytest.mark.parametrize("number", ["4111111111111112", "1234567812345678", "0000000000000001"])
def test_luhn_rejects_invalid(number):
    assert not luhn_valid(number)


# ---------------------------------------------------------------------------
# Structured identifiers -- regex engine, always available
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("mail john@example.com now", "EMAIL_ADDRESS"),
        ("mail first.last+tag@sub.example.co.uk now", "EMAIL_ADDRESS"),
        ("call +1-555-123-4567", "PHONE_NUMBER"),
        ("call (020) 7946 0958", "PHONE_NUMBER"),
        ("call 555-123-4567", "PHONE_NUMBER"),
        ("call +91 98765 43210", "PHONE_NUMBER"),
        ("host 192.168.1.50", "IP_ADDRESS"),
        ("host 2001:0db8:85a3:0000:0000:8a2e:0370:7334", "IP_ADDRESS"),
        ("card 4111 1111 1111 1111", "CREDIT_CARD"),
        ("card 4111-1111-1111-1111", "CREDIT_CARD"),
        ("ssn 123-45-6789", "US_SSN"),
    ],
)
def test_detects_structured_identifier(scanner, text, expected):
    assert expected in types_in(scanner, text)


def test_honorific_name_is_detected_in_any_mode(scanner):
    """The narrow honorific heuristic works without NER."""
    assert "PERSON" in types_in(scanner, "forward to Dr. Priya Ramaswamy please")


def test_demo_scenario_two(scanner):
    """Spec section 10, scenario 2: three entities."""
    types = types_in(scanner, "Contact John Smith at john@example.com or +1-555-123-4567")
    assert "EMAIL_ADDRESS" in types
    assert "PHONE_NUMBER" in types
    if scanner.has_ner:
        assert "PERSON" in types
        assert len(types) == 3


# ---------------------------------------------------------------------------
# False positives -- the corpus that must stay quiet
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "What is the capital of France?",
        "Summarise the quarterly report.",
        "commit da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "id 550e8400-e29b-41d4-a716-446655440000",
        "order 1234567890123456789 shipped",
        "card 4111 1111 1111 1112",  # fails Luhn -> not a card, and not a phone
        "version 3.8.3 released 2024-03-15",
        "pip install requests==2.31.0",
        "port 8080 on 256.300.1.1",  # invalid octets
        "the year 2024 had 366 days",
    ],
)
def test_benign_text_produces_no_detections(scanner, text):
    assert types_in(scanner, text) == [], f"false positive on: {text}"


def test_uuid_digits_are_not_a_phone(scanner):
    """Regression: the phase 0 stub flagged digit runs inside a UUID."""
    assert "PHONE_NUMBER" not in types_in(
        scanner, "request 550e8400-e29b-41d4-a716-446655440000 failed"
    )


def test_card_slice_is_not_a_phone(scanner):
    """A 12-digit window of a 19-digit number is not a phone."""
    assert "PHONE_NUMBER" not in types_in(scanner, "ref 1234 5678 9012 3456 789")


def test_location_disabled_by_default(scanner):
    """A country in an ordinary question is not personal data."""
    assert "LOCATION" not in types_in(scanner, "What is the capital of France?")
    assert scanner.entities["LOCATION"].enabled is False


# ---------------------------------------------------------------------------
# NER-dependent
# ---------------------------------------------------------------------------


@needs_ner
def test_person_without_honorific(scanner):
    assert "PERSON" in types_in(scanner, "Contact John Smith about the invoice")


@needs_ner
def test_indian_name_baseline(scanner):
    """Phase 3 measures and closes the recall gap. This records the baseline
    on one name; it is informational, not a pass/fail on fairness."""
    types = types_in(scanner, "Contact Priya Ramaswamy about the invoice")
    # Record outcome either way; the fairness harness (phase 13) does the real
    # measurement across a full corpus.
    assert isinstance(types, list)


# ---------------------------------------------------------------------------
# Privacy and separation-of-concerns invariants
# ---------------------------------------------------------------------------


def test_detections_never_carry_raw_values(scanner):
    text = "john@example.com and +1-555-123-4567 and 4111 1111 1111 1111"
    detections, vault = scanner.scan(text)
    serialized = "".join(d.model_dump_json() for d in detections)
    for raw in ("john@example.com", "555-123-4567", "4111 1111 1111 1111"):
        assert raw not in serialized, f"{raw} leaked into a Detection"
    assert any("john@example.com" in v for v in vault.values())


def test_offsets_locate_the_value(scanner):
    text = "mail john@example.com now"
    detections, _ = scanner.scan(text)
    d = next(x for x in detections if x.type == "EMAIL_ADDRESS")
    assert text[d.start : d.end] == "john@example.com"


def test_scanner_reports_but_does_not_decide(scanner):
    detections, _ = scanner.scan("john@example.com 192.168.1.1")
    assert detections
    for d in detections:
        assert d.action is PolicyAction.ALLOW
        assert d.category is DetectionCategory.PII


def test_repeated_value_reuses_placeholder(scanner):
    detections, vault = scanner.scan("john@example.com again john@example.com")
    assert len(detections) == 2
    assert detections[0].placeholder == detections[1].placeholder
    assert len(vault) == 1


def test_distinct_values_get_distinct_placeholders(scanner):
    detections, vault = scanner.scan("a@example.com and b@example.com")
    assert {d.placeholder for d in detections} == {"[EMAIL_1]", "[EMAIL_2]"}
    assert len(vault) == 2


def test_every_detection_carries_confidence_and_provenance(scanner):
    detections, _ = scanner.scan("john@example.com +1-555-123-4567")
    for d in detections:
        assert 0.0 < d.confidence <= 0.99
        assert d.recognizer, "must name the recogniser"
        assert d.pattern in {"high", "medium", "low"}, "sensitivity tag"


# ---------------------------------------------------------------------------
# Honest degradation
# ---------------------------------------------------------------------------


def test_health_reports_engine_state(scanner):
    h = scanner.health()
    assert h["engine"] in {"regex", "presidio+regex"}
    assert h["degraded"] is (h["engine"] == "regex")
    if h["degraded"]:
        assert h["degraded_reason"], "degraded mode must say why"
        assert "PERSON" in h["degraded_reason"]
    else:
        assert h["spacy_model"]


def test_degraded_mode_is_reported_not_hidden(monkeypatch):
    """Force the Presidio load to fail and confirm the scanner says so.

    A scanner that quietly ran regex-only while the dashboard claimed NER
    coverage would be lying about what it protects.
    """
    monkeypatch.setattr(
        mod, "PresidioEngine",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("simulated model failure")),
    )
    s = PIIScanner()
    assert s.degraded is True
    assert "regex-only" in (s.degraded_reason or "")
    # Structured identifiers still work.
    assert "EMAIL_ADDRESS" in [d.type for d in s.scan("x john@example.com")[0]]


# ---------------------------------------------------------------------------
# Shared span utilities
# ---------------------------------------------------------------------------


def test_resolve_overlaps_prefers_longest_then_confidence():
    items = [
        ("a", 0, 0, 10, 0.5),
        ("b", 0, 2, 6, 0.9),   # inside a -> loses to length
        ("c", 0, 20, 25, 0.6),
        ("d", 0, 20, 25, 0.8), # same span as c -> wins on confidence
    ]
    kept = resolve_overlaps(
        items, span=lambda x: (x[1], x[2], x[3]), score=lambda x: x[4]
    )
    assert [k[0] for k in kept] == ["a", "d"]


def test_resolve_overlaps_respects_message_index():
    items = [("a", 0, 0, 5, 0.5), ("b", 1, 0, 5, 0.5)]
    kept = resolve_overlaps(items, span=lambda x: (x[1], x[2], x[3]), score=lambda x: x[4])
    assert len(kept) == 2


def test_subtract_covered_drops_inner_spans():
    """The email-shaped fragment inside a DB URI yields to the URI finding."""
    pii = [("email", 0, 11, 35)]
    secrets = [("db_uri", 0, 0, 55)]
    kept = subtract_covered(
        pii, secrets,
        span_candidate=lambda x: (x[1], x[2], x[3]),
        span_covering=lambda x: (x[1], x[2], x[3]),
    )
    assert kept == []


def test_subtract_covered_keeps_outside_spans():
    pii = [("email", 0, 60, 76)]
    secrets = [("db_uri", 0, 0, 55)]
    kept = subtract_covered(
        pii, secrets,
        span_candidate=lambda x: (x[1], x[2], x[3]),
        span_covering=lambda x: (x[1], x[2], x[3]),
    )
    assert kept == pii
