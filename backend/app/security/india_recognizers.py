"""India-specific PII recognisers.

Requirement 5 (diversity, non-discrimination, fairness) groundwork. Stock
detection models are trained mostly on Western text; the measured result in
Phase 2 was that "John Smith" is caught and "Priya Ramaswamy" is missed in
the same sentence. This module adds:

  * structured Indian identifiers -- Aadhaar (Verhoeff-validated), PAN,
    IFSC, UPI VPA, Indian mobile numbers
  * a name gazetteer that lifts PERSON recall on Indian names

Design choice: this is an always-on engine alongside the regex engine, not a
set of Presidio custom recognisers. Presidio-only recognisers would vanish
in degraded (regex-only) mode, which is exactly when a fallback matters
most. The build plan said "register as Presidio recognisers"; this is a
strict superset of that.

Like every scanner, this module reports and never decides.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from app.config import CONFIG_DIR
from app.security.pii_scanner import PIIMatch, _digits_in_surrounding_run

NAMES_CONFIG_PATH = CONFIG_DIR / "india_names.yaml"


# ---------------------------------------------------------------------------
# Verhoeff checksum -- used by UIDAI for Aadhaar
# ---------------------------------------------------------------------------

_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_valid(number: str) -> bool:
    """True if the trailing digit is a correct Verhoeff check digit."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][ord(ch) - 48]]
    return c == 0


def verhoeff_check_digit(number: str) -> str:
    """Check digit to append to `number` so the result passes verhoeff_valid."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[(i + 1) % 8][ord(ch) - 48]]
    return str(_INV[c])


# ---------------------------------------------------------------------------
# Structured identifiers
# ---------------------------------------------------------------------------

# Aadhaar: 12 digits, first digit 2-9, in groups of 4 or bare. Verhoeff on
# the last digit. Formats: 2345 6789 0123 | 2345-6789-0123 | 234567890123
_AADHAAR = re.compile(r"(?<!\d)([2-9]\d{3})[ \-]?(\d{4})[ \-]?(\d{4})(?!\d)")

# PAN: AAAAA9999A. The 4th letter encodes the holder type.
_PAN = re.compile(r"\b([A-Z]{3})([A-Z])([A-Z])(\d{4})([A-Z])\b")
_PAN_HOLDER_TYPES = set("PCHFATBLJG")  # person, company, HUF, firm, AOP, trust, BOI, local, juridical, govt

# IFSC: 4 letters (bank), a literal 0, 6 alphanumerics (branch).
_IFSC = re.compile(r"\b([A-Z]{4})0([A-Z0-9]{6})\b")
_KNOWN_BANK_CODES = {
    "SBIN", "HDFC", "ICIC", "UTIB", "PUNB", "BARB", "KKBK", "YESB", "IDIB", "CNRB",
    "UBIN", "IOBA", "BKID", "MAHB", "INDB", "FDRL", "KARB", "SIBL", "CSBK", "DLXB",
    "RATN", "TMBL", "KVBL", "CIUB", "JAKA", "IDFB", "AUBL", "BDBL", "ESFB", "UJVN",
    "PYTM", "AIRP", "FINO", "DBSS", "SCBL", "HSBC", "CITI", "ANDB", "CORP", "ORBC",
    "ALLA", "SYNB", "VIJB", "UCBA", "CBIN", "PSIB", "BKDN", "IBKL",
}

# UPI VPA: handle@psp. No TLD -- that is what separates it from an email.
_UPI_PSPS = (
    "okaxis|okhdfcbank|okicici|oksbi|ybl|ibl|axl|paytm|apl|upi|sbi|icici|hdfcbank|"
    "axisbank|kotak|yesbank|idfcbank|indus|federal|barodampay|cnrb|pnb|boi|"
    "unionbankofindia|waaxis|wahdfcbank|waicici|wasbi|freecharge|mobikwik|"
    "jupiteraxis|fam|slice|airtel|jio|rbl|dbs|citi|hsbc|abfspay|ikwik|naviaxis|"
    "postbank|pingpay|fbl|kmbl|axisb|yapl|yesg|timecosmos|tapicici"
)
_UPI = re.compile(rf"(?<![\w.\-])([A-Za-z0-9._\-]{{2,64}})@({_UPI_PSPS})(?![\w.])", re.IGNORECASE)

# Indian mobile: 10 digits starting 6-9. Optional +91 / 91 / 0 prefix.
# Groupings seen in practice: 98765 43210 | 98765-43210 | 9876543210
_IN_MOBILE = re.compile(
    r"(?<![\w.\-])"
    r"(?:(\+91|91|0)[\s\-]?)?"
    r"([6-9]\d{4})[\s\-]?(\d{5})"
    r"(?![\w\-])"
)


# ---------------------------------------------------------------------------
# Name gazetteer
# ---------------------------------------------------------------------------

_CAP_RUN = re.compile(r"\b([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){0,3})\b")
_CUE_BEFORE = re.compile(r"([A-Za-z]+)[\s:,]+$")

# Capitalised words that commonly *precede* a name at sentence start and are
# never part of it. Stripped from the front of a run so "Meet Arjun Mehta"
# yields the span "Arjun Mehta", not the verb as well.
_LEADING_STOP = frozenset(
    "the this that these those please and for our your my his her their "
    "with from meet contact dear hi hello thanks regards attn attention "
    "cc to ask call tell email patient customer employee candidate applicant "
    "student welcome introducing".split()
)


@dataclass(frozen=True)
class Gazetteer:
    first_names: frozenset[str]
    surnames: frozenset[str]
    contact_cues: frozenset[str]
    version: int

    @property
    def all_names(self) -> frozenset[str]:
        return self.first_names | self.surnames


def _load_gazetteer(path: Path) -> Gazetteer:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Gazetteer(
        first_names=frozenset(str(n) for n in raw.get("first_names", []) if len(str(n)) >= 3),
        surnames=frozenset(str(n) for n in raw.get("surnames", []) if len(str(n)) >= 3),
        contact_cues=frozenset(str(c).lower() for c in raw.get("contact_cues", [])),
        version=int(raw.get("version", 1)),
    )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class IndiaEngine:
    name = "india"

    def __init__(self, names_path: Path | None = None) -> None:
        self.gazetteer = _load_gazetteer(names_path or NAMES_CONFIG_PATH)

    def find(self, text: str, message_index: int) -> list[PIIMatch]:
        out: list[PIIMatch] = []
        out.extend(self._aadhaar(text, message_index))
        out.extend(self._pan(text, message_index))
        out.extend(self._ifsc(text, message_index))
        out.extend(self._upi(text, message_index))
        out.extend(self._mobile(text, message_index))
        out.extend(self._names(text, message_index))
        return out

    # -- identifiers ----------------------------------------------------------

    def _aadhaar(self, text: str, mi: int) -> list[PIIMatch]:
        out = []
        for m in _AADHAAR.finditer(text):
            digits = "".join(m.groups())
            if not verhoeff_valid(digits):
                continue  # random 12 digits are not an Aadhaar
            out.append(PIIMatch("IN_AADHAAR", m.group(0), m.start(), m.end(), 0.95,
                                "india.aadhaar_verhoeff", mi))
        return out

    def _pan(self, text: str, mi: int) -> list[PIIMatch]:
        out = []
        for m in _PAN.finditer(text):
            holder = m.group(2)
            conf = 0.90 if holder in _PAN_HOLDER_TYPES else 0.55
            out.append(PIIMatch("IN_PAN", m.group(0), m.start(), m.end(), conf,
                                "india.pan", mi))
        return out

    def _ifsc(self, text: str, mi: int) -> list[PIIMatch]:
        out = []
        for m in _IFSC.finditer(text):
            conf = 0.92 if m.group(1) in _KNOWN_BANK_CODES else 0.60
            out.append(PIIMatch("IN_IFSC", m.group(0), m.start(), m.end(), conf,
                                "india.ifsc", mi))
        return out

    def _upi(self, text: str, mi: int) -> list[PIIMatch]:
        out = []
        for m in _UPI.finditer(text):
            out.append(PIIMatch("IN_UPI_ID", m.group(0), m.start(), m.end(), 0.88,
                                "india.upi_vpa", mi))
        return out

    def _mobile(self, text: str, mi: int) -> list[PIIMatch]:
        out = []
        for m in _IN_MOBILE.finditer(text):
            prefix = m.group(1)
            run = _digits_in_surrounding_run(text, m.start(), m.end())
            if prefix:
                if run > 12:
                    continue
                conf = 0.90
            else:
                if run != 10:
                    continue  # a bare 10-digit slice of something longer
                conf = 0.65  # plausible but a bare number could be an order ID
            out.append(PIIMatch("PHONE_NUMBER", m.group(0), m.start(), m.end(), conf,
                                "india.mobile", mi))
        return out

    # -- names ----------------------------------------------------------------

    def _names(self, text: str, mi: int) -> list[PIIMatch]:
        g = self.gazetteer
        stop = _LEADING_STOP | g.contact_cues
        out = []
        for m in _CAP_RUN.finditer(text):
            # Token positions within the source text, so a trimmed run still
            # reports exact offsets.
            positions = [(t.start() + m.start(1), t.end() + m.start(1))
                         for t in re.finditer(r"\S+", m.group(1))]
            tokens = [text[a:b] for a, b in positions]

            # Strip leading stop words ("Meet", "Dear", "Contact") so the
            # reported span is the name alone. A stripped cue licenses a
            # single first name below.
            cued = False
            while tokens and tokens[0].lower() in stop and tokens[0] not in g.all_names:
                tokens.pop(0)
                positions.pop(0)
                cued = True
            if not tokens:
                continue
            span_start, span_end = positions[0][0], positions[-1][1]
            value = text[span_start:span_end]

            in_first = [t in g.first_names for t in tokens]
            in_sur = [t in g.surnames for t in tokens]
            hits = sum(a or b for a, b in zip(in_first, in_sur))

            if len(tokens) >= 2:
                if hits >= 2:
                    conf = 0.88
                elif hits == 1 and (in_first[0] or in_sur[-1]):
                    # first token is a known first name, or last is a known
                    # surname, and the rest is capitalised: strong pattern
                    conf = 0.74
                elif hits == 1:
                    conf = 0.60
                else:
                    continue
                out.append(PIIMatch("PERSON", value, span_start, span_end, conf,
                                    "india.name_gazetteer", mi))
                continue

            # Single token: only a first name, and only after a contact cue --
            # either one just stripped, or a lower-case one before the run.
            if in_first[0]:
                if not cued:
                    before = _CUE_BEFORE.search(text[:span_start])
                    cued = bool(before and before.group(1).lower() in g.contact_cues)
                if cued:
                    out.append(PIIMatch("PERSON", value, span_start, span_end, 0.66,
                                        "india.name_gazetteer_cued", mi))
        return out


@lru_cache
def get_india_engine() -> IndiaEngine:
    return IndiaEngine()
