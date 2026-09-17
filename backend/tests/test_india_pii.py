"""Phase 3 -- India-specific recognisers and the name gazetteer.

Every test here runs in both engine modes: the India engine is always on,
independent of Presidio. That is the point -- the fairness fix must not
vanish when the ML model is absent.
"""

from __future__ import annotations

import pytest

from app.contracts.common import DetectionCategory, PolicyAction
from app.security import pii_scanner as mod
from app.security.india_recognizers import (
    IndiaEngine,
    get_india_engine,
    verhoeff_check_digit,
    verhoeff_valid,
)
from app.security.pii_scanner import PIIScanner, get_pii_scanner


@pytest.fixture(scope="module")
def scanner() -> PIIScanner:
    s = get_pii_scanner()
    s.warm()
    return s


@pytest.fixture(scope="module")
def degraded_scanner(monkeypatch_module) -> PIIScanner:
    """A scanner with Presidio forcibly unavailable -- regex + India only."""
    monkeypatch_module.setattr(
        mod, "PresidioEngine",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("forced: no NER")),
    )
    s = PIIScanner()
    assert s.degraded
    return s


@pytest.fixture(scope="module")
def monkeypatch_module():
    from _pytest.monkeypatch import MonkeyPatch

    mp = MonkeyPatch()
    yield mp
    mp.undo()


def types_in(s: PIIScanner, text: str) -> list[str]:
    return [d.type for d in s.scan(text)[0]]


def persons_in(s: PIIScanner, text: str) -> list[str]:
    return [text[d.start : d.end] for d in s.scan(text)[0] if d.type == "PERSON"]


VALID_AADHAAR = "2345 6789 0124"  # check digit computed by verhoeff_check_digit


# ---------------------------------------------------------------------------
# Verhoeff
# ---------------------------------------------------------------------------


def test_verhoeff_published_vector():
    """Wikipedia's worked example: 236 -> check digit 3."""
    assert verhoeff_check_digit("236") == "3"
    assert verhoeff_valid("2363")
    assert not verhoeff_valid("2364")


@pytest.mark.parametrize("base", ["23456789012", "98765432109", "50000000000", "31415926535"])
def test_verhoeff_round_trip(base):
    full = base + verhoeff_check_digit(base)
    assert verhoeff_valid(full)
    # every other check digit fails
    for wrong in "0123456789":
        if wrong != full[-1]:
            assert not verhoeff_valid(base + wrong)


def test_verhoeff_catches_transposition():
    """Verhoeff is designed to catch adjacent transpositions, unlike Luhn."""
    full = "23456789012" + verhoeff_check_digit("23456789012")
    swapped = full[:5] + full[6] + full[5] + full[7:]
    assert full != swapped
    assert not verhoeff_valid(swapped)


# ---------------------------------------------------------------------------
# Aadhaar
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        f"Aadhaar {VALID_AADHAAR}",
        f"Aadhaar {VALID_AADHAAR.replace(' ', '-')}",
        f"Aadhaar {VALID_AADHAAR.replace(' ', '')}",
    ],
)
def test_aadhaar_formats(scanner, text):
    assert "IN_AADHAAR" in types_in(scanner, text)


def test_aadhaar_invalid_checksum_is_not_aadhaar(scanner):
    """Twelve digits are not an Aadhaar. Twelve digits with a valid Verhoeff
    check digit are."""
    types = types_in(scanner, "Aadhaar 2345 6789 0123")
    assert "IN_AADHAAR" not in types
    assert "PHONE_NUMBER" not in types, "4-4-4 grouping is not a phone either"


def test_aadhaar_cannot_start_with_0_or_1(scanner):
    base = "12345678901"
    full = base + verhoeff_check_digit(base)
    assert verhoeff_valid(full), "checksum is fine; the leading digit is what rejects it"
    assert "IN_AADHAAR" not in types_in(scanner, f"id {full[:4]} {full[4:8]} {full[8:]}")


def test_aadhaar_works_without_ner(degraded_scanner):
    assert "IN_AADHAAR" in types_in(degraded_scanner, f"Aadhaar {VALID_AADHAAR}")


# ---------------------------------------------------------------------------
# PAN
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pan", "holder"),
    [("ABCPE1234F", "person"), ("ABCCE1234F", "company"), ("ABCHE1234F", "HUF"), ("ABCFE1234F", "firm")],
)
def test_pan_valid_holder_types(scanner, pan, holder):
    dets, _ = scanner.scan(f"PAN {pan}")
    d = next(x for x in dets if x.type == "IN_PAN")
    assert d.confidence >= 0.85, holder


def test_pan_invalid_holder_type_below_threshold(scanner):
    """X is not a holder type; the finding is scored low and filtered."""
    assert "IN_PAN" not in types_in(scanner, "PAN ABCXE1234F")


@pytest.mark.parametrize("text", ["abcpe1234f", "ABCPE12345", "ABCP1234F", "ABCPE1234FG"])
def test_pan_shape_must_be_exact(scanner, text):
    assert "IN_PAN" not in types_in(scanner, f"ref {text}")


# ---------------------------------------------------------------------------
# IFSC
# ---------------------------------------------------------------------------


def test_ifsc_known_bank_high_confidence(scanner):
    dets, _ = scanner.scan("IFSC SBIN0001234")
    d = next(x for x in dets if x.type == "IN_IFSC")
    assert d.confidence >= 0.90


def test_ifsc_unknown_bank_still_reported_lower(scanner):
    dets, _ = scanner.scan("IFSC ZZZZ0001234")
    d = next(x for x in dets if x.type == "IN_IFSC")
    assert 0.5 <= d.confidence < 0.90


def test_ifsc_fifth_char_must_be_zero(scanner):
    assert "IN_IFSC" not in types_in(scanner, "IFSC SBIN1001234")


# ---------------------------------------------------------------------------
# UPI
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vpa", ["priya.r@okaxis", "9876543210@paytm", "rahul_k@ybl", "shop-1@upi"])
def test_upi_known_psp(scanner, vpa):
    assert "IN_UPI_ID" in types_in(scanner, f"pay to {vpa} today")


def test_email_with_tld_is_email_not_upi(scanner):
    """priya@sbi.co.in has a TLD. UPI handles do not."""
    types = types_in(scanner, "mail priya@sbi.co.in")
    assert types == ["EMAIL_ADDRESS"]


def test_unknown_psp_is_not_upi(scanner):
    assert "IN_UPI_ID" not in types_in(scanner, "handle user@notapsp")


# ---------------------------------------------------------------------------
# Indian mobile
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text", ["call +91 98765 43210", "call +91-98765-43210", "call 098765 43210", "call 9876543210"]
)
def test_indian_mobile_formats(scanner, text):
    assert "PHONE_NUMBER" in types_in(scanner, text)


def test_indian_mobile_leading_digit_must_be_6_to_9(scanner):
    assert "PHONE_NUMBER" not in types_in(scanner, "call 5876543210")


def test_bare_ten_digits_inside_longer_number_is_not_mobile(scanner):
    assert "PHONE_NUMBER" not in types_in(scanner, "order 98765432101234 shipped")


def test_bare_mobile_has_lower_confidence_than_prefixed(scanner):
    bare = next(d for d in scanner.scan("call 9876543210")[0] if d.type == "PHONE_NUMBER")
    pref = next(d for d in scanner.scan("call +91 9876543210")[0] if d.type == "PHONE_NUMBER")
    assert bare.confidence < pref.confidence


# ---------------------------------------------------------------------------
# Name gazetteer -- Requirement 5
# ---------------------------------------------------------------------------


def test_the_fairness_pair(scanner):
    """The Phase 2 baseline: John caught, Priya missed. Both must be caught now."""
    assert persons_in(scanner, "Contact John Smith at john@example.com") == ["John Smith"]
    assert persons_in(scanner, "Contact Priya Ramaswamy at priya@example.in") == ["Priya Ramaswamy"]


def test_fairness_pair_holds_without_ner(degraded_scanner):
    """The fix must survive the model being absent -- that is the whole point
    of an always-on engine rather than a Presidio-only recogniser."""
    assert persons_in(degraded_scanner, "Contact Priya Ramaswamy at priya@example.in") == [
        "Priya Ramaswamy"
    ]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Meet Arjun Mehta tomorrow", ["Arjun Mehta"]),
        ("Please forward to Fatima Siddiqui", ["Fatima Siddiqui"]),
        ("Gurpreet Kaur signed the form", ["Gurpreet Kaur"]),
        ("Karthikeya Gupta will present", ["Karthikeya Gupta"]),
        ("Contact Lakshmi Iyer and Rohan Fernandes", ["Lakshmi Iyer", "Rohan Fernandes"]),
    ],
)
def test_gazetteer_regional_coverage(degraded_scanner, text, expected):
    """Run in degraded mode so the gazetteer, not NER, is what is being tested."""
    assert persons_in(degraded_scanner, text) == expected


def test_span_excludes_leading_verb(degraded_scanner):
    """Redacting 'Meet Arjun Mehta' as one placeholder would eat the verb."""
    dets, _ = degraded_scanner.scan("Meet Arjun Mehta tomorrow")
    d = next(x for x in dets if x.type == "PERSON")
    assert "Meet Arjun Mehta tomorrow"[d.start : d.end] == "Arjun Mehta"


def test_single_first_name_needs_a_cue(degraded_scanner):
    assert persons_in(degraded_scanner, "Dear Priya, your order shipped") == ["Priya"]
    assert persons_in(degraded_scanner, "contact Priya about it") == ["Priya"]
    # No cue: a lone capitalised first name is too ambiguous to flag.
    assert persons_in(degraded_scanner, "Priya is a common name") == []


def test_mixed_origin_name_is_caught(degraded_scanner):
    """Known first name + unknown capitalised surname: still a person."""
    assert persons_in(degraded_scanner, "Contact Arjun Whitfield today") == ["Arjun Whitfield"]


@pytest.mark.parametrize(
    "text",
    [
        "Contact Support Team for help",
        "Gupta Enterprises Limited",
        "The Sharma Report is due",  # one surname + non-name words: below threshold
        "New Delhi Railway Station",
        "Reserve Bank of India",
    ],
)
def test_gazetteer_false_positive_corpus(degraded_scanner, text):
    assert persons_in(degraded_scanner, text) == [], f"false positive on: {text}"


def test_gazetteer_loads_from_config():
    g = get_india_engine().gazetteer
    assert len(g.first_names) >= 150
    assert len(g.surnames) >= 120
    assert "Priya" in g.first_names and "Ramaswamy" in g.surnames
    assert all(len(n) >= 3 for n in g.all_names), "short tokens are excluded"


# ---------------------------------------------------------------------------
# Demo scenario 3 -- the exit criterion
# ---------------------------------------------------------------------------


def test_demo_scenario_three(scanner):
    text = (
        f"Contact Priya Ramaswamy at priya@example.in or +91 98765 43210. "
        f"Aadhaar {VALID_AADHAAR}, PAN ABCPE1234F, UPI priya.r@okaxis"
    )
    dets, vault = scanner.scan(text)
    found = {d.type for d in dets}
    assert {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IN_AADHAAR", "IN_PAN", "IN_UPI_ID"} <= found
    assert "Priya Ramaswamy" in vault.values()


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


def test_detections_never_carry_raw_values(scanner):
    text = f"Priya Ramaswamy, Aadhaar {VALID_AADHAAR}, PAN ABCPE1234F"
    dets, vault = scanner.scan(text)
    serialized = "".join(d.model_dump_json() for d in dets)
    for raw in ("Ramaswamy", VALID_AADHAAR, "ABCPE1234F"):
        assert raw not in serialized
    assert VALID_AADHAAR in vault.values()


def test_india_engine_reports_but_does_not_decide(scanner):
    dets, _ = scanner.scan(f"Aadhaar {VALID_AADHAAR} PAN ABCPE1234F")
    for d in dets:
        assert d.action is PolicyAction.ALLOW
        assert d.category is DetectionCategory.PII
        assert d.recognizer.startswith("india.")


def test_health_reports_gazetteer_size(scanner):
    assert scanner.health()["india_gazetteer_names"] >= 250


# ---------------------------------------------------------------------------
# Known misses -- documented, not hidden
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("contact priya ramaswamy", "all-lowercase name"),
        ("PRIYA RAMASWAMY", "all-caps name"),
        ("Contact P. Ramaswamy", "initial + surname"),
    ],
)
def test_known_misses_are_documented(degraded_scanner, text, why):
    """Not caught by the gazetteer today. Feeds the limitations panel."""
    assert persons_in(degraded_scanner, text) == [], f"unexpectedly caught: {why}"


def test_known_limitation_hyphenated_surname_is_truncated(degraded_scanner):
    """A hyphenated surname is caught, but the span stops at the hyphen.

    Redacting "Priyanka Chopra-Jonas" would leave "-Jonas" visible. Partial
    coverage is documented here rather than hidden; closing it means
    admitting hyphens into the capitalised-token pattern.
    """
    assert persons_in(degraded_scanner, "Contact Priyanka Chopra-Jonas") == ["Priyanka Chopra"]
