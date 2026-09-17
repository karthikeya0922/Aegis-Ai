"""Heuristic Prompt-Injection Defense -- OWASP LLM01.

What this is: a rule engine over normalised text that recognises known
injection phrasings and their common obfuscations, and scores them.

What this is not: a guarantee. Novel attacks, attacks in other languages,
and attacks embedded in retrieved documents rather than the prompt are not
caught here. The spec forbids claiming otherwise, and the UI shows the
limitations panel for that reason.

Pipeline for one text:

    raw text
      -> normalise      NFKC, strip zero-width, fold confusables, collapse ws, lower
      -> variants       base | leet-folded | letter-spacing-collapsed
      -> base64 probe   decode candidate blobs, scan the plaintext too
      -> match rules    every variant, every rule; note which variant hit
      -> score          per-category max, then noisy-OR across categories
      -> InjectionFinding(detected, score, matched_rules, categories)

Like every scanner, this reports and never decides. `detected` is simply
`score >= threshold`; the policy engine (phase 6) maps that to BLOCK, and
the block is appealable -- a heuristic can be wrong and a human can say so.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from app.config import settings
from app.contracts.common import InjectionFinding

# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿­]")
# Horizontal whitespace collapses to one space; newlines are preserved (as a
# single "\n") because the delimiter rules anchor on line starts.
_HWS = re.compile(r"[^\S\n]+")
_NL = re.compile(r"\n[\s]*\n|\n")
_ALL_WS = re.compile(r"\s+")

# Confusables that commonly stand in for Latin letters. Deliberately small:
# the goal is to defeat the cheap trick, not to transliterate Cyrillic.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "к": "k", "т": "t", "в": "b", "н": "h", "м": "m",
    "А": "a", "Е": "e", "О": "o", "Р": "p", "С": "c", "Х": "x", "У": "y", "І": "i",
    "К": "k", "Т": "t", "В": "b", "Н": "h", "М": "m",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "ν": "v", "τ": "t", "κ": "k",
    "ⅰ": "i", "ⅼ": "l", "ⅴ": "v", "ⅹ": "x",
})

_LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
    "|": "l", "!": "i", "+": "t",
})

# "i g n o r e  p r e v i o u s" -- five or more single letters separated by
# exactly one space. Runs are joined into words; a wider gap between runs is
# what marks the word break, so this must run BEFORE whitespace collapses.
_SPACED_LETTERS = re.compile(r"(?:\b[a-z] ){4,}[a-z]\b")

# Base64-looking blobs worth trying to decode.
_B64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_MAX_B64_CANDIDATES = 5
_MAX_B64_BYTES = 4096


@dataclass
class Normalised:
    base: str
    leet: str
    despaced: str
    compact: str  # every whitespace character removed
    had_zero_width: bool
    had_confusables: bool
    had_spaced_letters: bool
    decoded_payloads: list[str] = field(default_factory=list)


def _fold_confusables(text: str) -> tuple[str, bool]:
    folded = text.translate(_CONFUSABLES)
    return folded, folded != text


def _collapse_spaced_letters(text: str) -> tuple[str, bool]:
    changed = False

    def _join(m: re.Match[str]) -> str:
        nonlocal changed
        changed = True
        return m.group(0).replace(" ", "")

    return _SPACED_LETTERS.sub(_join, text), changed


def _decode_base64_candidates(text: str) -> list[str]:
    out: list[str] = []
    for m in _B64_CANDIDATE.finditer(text):
        if len(out) >= _MAX_B64_CANDIDATES:
            break
        blob = m.group(0)
        if len(blob) > _MAX_B64_BYTES:
            continue
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(ch.isprintable() or ch in "\n\t" for ch in decoded)
        if decoded and printable / len(decoded) >= 0.9 and any(ch.isalpha() for ch in decoded):
            out.append(decoded)
    return out


def normalise(text: str) -> Normalised:
    had_zw = bool(_ZERO_WIDTH.search(text))
    t = _ZERO_WIDTH.sub("", text)
    t = unicodedata.normalize("NFKC", t)
    t, had_conf = _fold_confusables(t)
    t = t.lower()

    # Spaced-letter collapse runs on the raw spacing, where a double space
    # still marks a word boundary. Then whitespace is normalised for both.
    despaced_raw, had_spaced = _collapse_spaced_letters(t)

    def _ws(s: str) -> str:
        s = _HWS.sub(" ", s)
        s = _NL.sub("\n", s)
        return s.strip()

    base = _ws(t)
    despaced = _ws(despaced_raw)
    leet = base.translate(_LEET)
    compact = _ALL_WS.sub("", base)

    return Normalised(
        base=base,
        leet=leet,
        despaced=despaced,
        compact=compact,
        had_zero_width=had_zw,
        had_confusables=had_conf,
        had_spaced_letters=had_spaced,
        decoded_payloads=_decode_base64_candidates(text),
    )


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: float
    regex: re.Pattern[str]
    description: str = ""


@dataclass(frozen=True)
class CompactSignature:
    id: str
    category: str
    weight: float
    needle: str


@dataclass
class RuleSet:
    version: int
    rules: list[Rule]
    categories: dict[str, dict]
    synthetic: dict[str, float]
    compact: list[CompactSignature]


def _load_rules(path: Path) -> RuleSet:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = [
        Rule(
            id=r["id"],
            category=r["category"],
            weight=float(r["weight"]),
            regex=re.compile(r["regex"], re.MULTILINE),
            description=(r.get("description") or "").strip(),
        )
        for r in raw.get("rules", [])
    ]
    compact = [
        CompactSignature(
            id=c["id"], category=c["category"], weight=float(c["weight"]),
            needle=str(c["needle"]).lower(),
        )
        for c in raw.get("compact_signatures", [])
    ]
    return RuleSet(
        version=int(raw.get("version", 1)),
        rules=rules,
        categories=raw.get("categories") or {},
        synthetic={k: float(v) for k, v in (raw.get("synthetic_rules") or {}).items()},
        compact=compact,
    )


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


@dataclass
class Match:
    rule_id: str
    category: str
    weight: float
    via: str  # base | leet | despaced | base64


class InjectionDetector:
    def __init__(self, rules_path: Path | None = None) -> None:
        self.ruleset = _load_rules(rules_path or settings.injection_rules_path)

    # -- matching ------------------------------------------------------------

    def _match_variant(self, text: str, via: str) -> list[Match]:
        out: list[Match] = []
        for rule in self.ruleset.rules:
            if rule.regex.search(text):
                out.append(Match(rule.id, rule.category, rule.weight, via))
        return out

    def matches(self, text: str) -> tuple[list[Match], Normalised]:
        n = normalise(text)
        found: dict[str, Match] = {}

        # Base pass first so a rule that matches plainly is recorded as such.
        for m in self._match_variant(n.base, "base"):
            found[m.rule_id] = m
        # De-obfuscation passes only add rules the base pass missed.
        if n.leet != n.base:
            for m in self._match_variant(n.leet, "leet"):
                found.setdefault(m.rule_id, m)
        if n.had_spaced_letters:
            for m in self._match_variant(n.despaced, "despaced"):
                found.setdefault(m.rule_id, m)
        for payload in n.decoded_payloads:
            inner = normalise(payload)
            for m in self._match_variant(inner.base, "base64"):
                found.setdefault(m.rule_id, m)
        # Whitespace-free fallback: catches uniformly spaced letters and
        # run-together words that no boundary-based regex can see.
        compact_hit = False
        for sig in self.ruleset.compact:
            if sig.needle in n.compact and sig.id not in found:
                # Only credit the compact match if no regex rule already
                # covers the same category -- otherwise it is redundant.
                if not any(m.category == sig.category for m in found.values()):
                    found[sig.id] = Match(sig.id, sig.category, sig.weight, "compact")
                    compact_hit = True

        result = list(found.values())
        syn = self.ruleset.synthetic
        if compact_hit:
            result.append(Match("evasion.compact_match", "encoding_evasion", syn["evasion.compact_match"], "compact"))

        # Synthetic evasion signals: only meaningful when some rule matched
        # through the corresponding de-obfuscation, or when the raw text
        # carried an obfuscation marker at all.
        if any(m.via == "leet" for m in result):
            result.append(Match("evasion.leetspeak", "encoding_evasion", syn["evasion.leetspeak"], "leet"))
        if any(m.via == "despaced" for m in result):
            result.append(Match("evasion.spaced_letters", "encoding_evasion", syn["evasion.spaced_letters"], "despaced"))
        if any(m.via == "base64" for m in result):
            result.append(Match("evasion.base64_payload", "encoding_evasion", syn["evasion.base64_payload"], "base64"))
        if n.had_confusables and result:
            result.append(Match("evasion.homoglyph", "encoding_evasion", syn["evasion.homoglyph"], "base"))
        if n.had_zero_width and result:
            result.append(Match("evasion.zero_width", "encoding_evasion", syn["evasion.zero_width"], "base"))

        return result, n

    # -- scoring -------------------------------------------------------------

    @staticmethod
    def score(matches: list[Match]) -> float:
        """Per-category max, then noisy-OR across categories.

        Five phrasings of the same override do not stack; an override plus
        an extraction attempt does. Bounded in [0, 1].
        """
        per_cat: dict[str, float] = {}
        for m in matches:
            per_cat[m.category] = max(per_cat.get(m.category, 0.0), m.weight)
        miss = 1.0
        for s in per_cat.values():
            miss *= 1.0 - s
        return round(1.0 - miss, 3)

    # -- public API ----------------------------------------------------------

    def analyze(self, text: str, threshold: float | None = None) -> InjectionFinding:
        limit = threshold if threshold is not None else settings.injection_threshold
        matched, _ = self.matches(text)
        s = self.score(matched)
        ordered = sorted(matched, key=lambda m: (-m.weight, m.rule_id))
        return InjectionFinding(
            detected=s >= limit,
            score=s,
            matched_rules=[m.rule_id for m in ordered],
            categories=sorted({m.category for m in ordered}),
        )

    def explain(self, finding: InjectionFinding) -> str:
        """Plain-language reason for the UI (Requirement 4)."""
        if not finding.matched_rules:
            return "No injection patterns matched."
        labels = [
            self.ruleset.categories.get(c, {}).get("label", c) for c in finding.categories
        ]
        top = finding.matched_rules[0]
        verdict = "blocked" if finding.detected else "flagged but below the block threshold"
        return (
            f"The prompt matched {len(finding.matched_rules)} injection rule(s) "
            f"across {', '.join(labels)} (strongest: {top}); score {finding.score:.2f}, {verdict}."
        )


@lru_cache
def get_detector() -> InjectionDetector:
    return InjectionDetector()
