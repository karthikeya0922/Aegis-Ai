"""Egress screens: harm and bias checks on the model's response.

Heuristic, pattern-based, config-driven (config/egress_screens.yaml). Same
scoring as the injection detector -- per-category max, noisy-OR across
categories -- and the same honesty: this catches blunt cases and misses
subtle ones, and says so.

The bias screen is Requirement 5 on the output side. It matches a demeaning
FRAME around a generic group noun ("all X are", "X don't deserve to") rather
than carrying a list of insults, so the repository contains no slurs and
the screen still catches the pattern.

Like every scanner: these report, the policy engine decides.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from app.config import CONFIG_DIR
from app.contracts.egress import BiasResult, SafetyResult

SCREENS_PATH = CONFIG_DIR / "egress_screens.yaml"

_WS = re.compile(r"\s+")


@dataclass(frozen=True)
class Category:
    name: str
    weight: float
    patterns: tuple[re.Pattern[str], ...]


@dataclass(frozen=True)
class Screen:
    name: str
    threshold: float
    categories: tuple[Category, ...]


@dataclass
class ScreenHit:
    category: str
    weight: float
    pattern_index: int


@dataclass
class ScreenOutcome:
    flagged: bool
    score: float
    categories: list[str]
    hits: list[ScreenHit] = field(default_factory=list)


@dataclass(frozen=True)
class Screens:
    version: int
    harm: Screen
    bias: Screen
    fallbacks: dict[str, str]


def _normalise(text: str) -> str:
    t = unicodedata.normalize("NFKC", text)
    return _WS.sub(" ", t).strip().lower()


def _compile(raw: dict, group_terms: str | None) -> tuple[Category, ...]:
    cats = []
    for name, spec in (raw.get("categories") or {}).items():
        pats = []
        for p in spec.get("patterns", []):
            src = str(p)
            if group_terms is not None:
                src = src.replace("GROUP", group_terms)
            pats.append(re.compile(src, re.IGNORECASE))
        cats.append(Category(name=str(name), weight=float(spec.get("weight", 0.5)), patterns=tuple(pats)))
    return tuple(cats)


@lru_cache
def load_screens(path: Path | None = None) -> Screens:
    raw = yaml.safe_load((path or SCREENS_PATH).read_text(encoding="utf-8"))
    harm_raw = raw.get("harm") or {}
    bias_raw = raw.get("bias") or {}
    group_terms = "(?:" + _WS.sub("", str(bias_raw.get("group_terms", ""))) + ")"
    return Screens(
        version=int(raw.get("version", 1)),
        harm=Screen("harm", float(harm_raw.get("threshold", 0.7)), _compile(harm_raw, None)),
        bias=Screen("bias", float(bias_raw.get("threshold", 0.6)), _compile(bias_raw, group_terms)),
        fallbacks={str(k): " ".join(str(v).split()) for k, v in (raw.get("fallbacks") or {}).items()},
    )


def _score(screen: Screen, text: str) -> ScreenOutcome:
    norm = _normalise(text)
    hits: list[ScreenHit] = []
    per_cat: dict[str, float] = {}
    for cat in screen.categories:
        for i, pat in enumerate(cat.patterns):
            if pat.search(norm):
                hits.append(ScreenHit(cat.name, cat.weight, i))
                per_cat[cat.name] = max(per_cat.get(cat.name, 0.0), cat.weight)
                break  # one hit per category is enough for the max
    miss = 1.0
    for s in per_cat.values():
        miss *= 1.0 - s
    score = round(1.0 - miss, 3)
    return ScreenOutcome(
        flagged=score >= screen.threshold,
        score=score,
        categories=sorted(per_cat, key=lambda c: -per_cat[c]),
        hits=hits,
    )


def screen_harm(text: str) -> SafetyResult:
    o = _score(load_screens().harm, text)
    return SafetyResult(flagged=o.flagged, categories=o.categories, score=min(o.score, 1.0))


def screen_bias(text: str) -> BiasResult:
    o = _score(load_screens().bias, text)
    return BiasResult(flagged=o.flagged, signals=o.categories, score=min(o.score, 1.0))


def fallback_text(kind: str) -> str:
    return load_screens().fallbacks.get(kind, "This response was withheld by Aegis policy.")
