"""Fairness evaluation harness for the PERSON detector (Requirement 5).

A privacy tool that protects some people's identities more reliably than
others is an unfair system. This module measures that directly: the same
sentence templates, five name-origin groups, recall per group, and the gap
between the best- and worst-served group.

Two configurations are run and persisted so the before/after is measured
live rather than remembered:

    baseline  -- NER only (the India gazetteer disabled). This is the stock
                 detector every competitor ships.
    current   -- the full scanner, gazetteer on.

Scoring is per sample: a sample is a hit when a PERSON detection covers
the whole name. A PERSON detection that does not overlap the name is a false
positive (the template tagged "Friday" as a person, say), which is what
precision measures.

What this does NOT claim: the corpus is fixed and synthetic, not a
representative population sample. It is indicative of relative detector
behaviour across groups, not an absolute accuracy figure. The API response
carries that disclaimer.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sqlalchemy import select

from app.audit.database import session_scope
from app.audit.models import FairnessEval
from app.config import EVAL_DIR
from app.contracts.governance import (
    FairnessGroupResult,
    FairnessReportResponse,
    FairnessRun,
)
from app.security.pii_scanner import PIIScanner, get_pii_scanner
from app.utils.ids import run_id as new_run_id
from app.utils.logging import get_logger

log = get_logger(__name__)

CORPUS_PATH = EVAL_DIR / "name_corpus.yaml"

BASELINE_LABEL = "baseline_ner_only"
CURRENT_LABEL = "current"

DISCLAIMER = (
    "Recall measured against a fixed synthetic name corpus, not a representative "
    "population sample. Indicative of relative detector behaviour across groups, "
    "not an absolute accuracy claim."
)
METHOD = (
    "Each name in each origin group is placed in the same sentence templates and "
    "run through the PII scanner. A sample counts as detected when a PERSON finding "
    "covers the whole name; a PERSON finding elsewhere in the sentence is a false "
    "positive. Baseline disables the India name gazetteer to measure the stock NER "
    "alone; current is the full scanner. Both runs use the same spaCy model."
)


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Corpus:
    version: int
    detector: str
    templates: tuple[str, ...]
    groups: dict[str, tuple[str, ...]]  # group key -> names
    labels: dict[str, str]


def load_corpus(path: Path | None = None) -> Corpus:
    raw = yaml.safe_load((path or CORPUS_PATH).read_text(encoding="utf-8"))
    groups = {k: tuple(str(n) for n in v["names"]) for k, v in raw["groups"].items()}
    labels = {k: str(v.get("label", k)) for k, v in raw["groups"].items()}
    templates = tuple(str(t) for t in raw["templates"])
    for t in templates:
        if t.count("{name}") != 1:
            raise ValueError(f"template must contain exactly one {{name}}: {t!r}")
    return Corpus(
        version=int(raw.get("version", 1)),
        detector=str(raw.get("detector", "pii.person")),
        templates=templates,
        groups=groups,
        labels=labels,
    )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


@dataclass
class GroupTally:
    total: int = 0
    hits: int = 0
    false_positives: int = 0
    by_engine: dict[str, int] = field(default_factory=dict)
    # Indian-only breakdown: names with a gazetteer token vs. without
    covered_total: int = 0
    covered_hits: int = 0
    held_out_total: int = 0
    held_out_hits: int = 0

    @property
    def recall(self) -> float:
        return self.hits / self.total if self.total else 0.0

    @property
    def precision(self) -> float | None:
        denom = self.hits + self.false_positives
        return self.hits / denom if denom else None

    @property
    def f1(self) -> float | None:
        p = self.precision
        r = self.recall
        if p is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)


def score_sample(scanner: PIIScanner, sentence: str, name: str) -> tuple[bool, str | None, int]:
    """Returns (hit, engine_that_caught_it, false_positive_count)."""
    start = sentence.index(name)
    end = start + len(name)
    dets, _ = scanner.scan(sentence)
    persons = [d for d in dets if d.type == "PERSON"]
    hit_engine: str | None = None
    fps = 0
    for d in persons:
        if d.start <= start and end <= d.end:
            # covers the whole name; prefer to report the first engine that did
            if hit_engine is None:
                hit_engine = d.recognizer.split(".")[0] if d.recognizer else "unknown"
        elif d.end <= start or d.start >= end:
            fps += 1
        # partial overlap (e.g. surname only) is neither a hit nor a false positive
    return hit_engine is not None, hit_engine, fps


# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    run_id: str
    label: str
    run_at: datetime
    engine: str
    tallies: dict[str, GroupTally]
    duration_s: float
    templates_used: int
    breakdown: dict[str, float]


def run_configuration(
    scanner: PIIScanner,
    corpus: Corpus,
    label: str,
    *,
    max_templates: int | None = None,
    max_names: int | None = None,
) -> RunResult:
    t0 = time.perf_counter()
    templates = corpus.templates[:max_templates] if max_templates else corpus.templates
    tallies: dict[str, GroupTally] = {g: GroupTally() for g in corpus.groups}
    india = scanner._india  # noqa: SLF001 - harness is an internal consumer

    for group, names in corpus.groups.items():
        t = tallies[group]
        for name in (names[:max_names] if max_names else names):
            covered = india.covers(name)
            for tmpl in templates:
                sentence = tmpl.replace("{name}", name)
                hit, engine, fps = score_sample(scanner, sentence, name)
                t.total += 1
                t.false_positives += fps
                if hit:
                    t.hits += 1
                    t.by_engine[engine or "unknown"] = t.by_engine.get(engine or "unknown", 0) + 1
                if group == "indian":
                    if covered:
                        t.covered_total += 1
                        t.covered_hits += int(hit)
                    else:
                        t.held_out_total += 1
                        t.held_out_hits += int(hit)

    breakdown: dict[str, float] = {}
    ind = tallies.get("indian")
    if ind:
        if ind.covered_total:
            breakdown["indian.gazetteer_covered.recall"] = round(ind.covered_hits / ind.covered_total, 4)
            breakdown["indian.gazetteer_covered.n"] = float(ind.covered_total)
        if ind.held_out_total:
            breakdown["indian.held_out.recall"] = round(ind.held_out_hits / ind.held_out_total, 4)
            breakdown["indian.held_out.n"] = float(ind.held_out_total)
    for g, t in tallies.items():
        for eng, n in t.by_engine.items():
            breakdown[f"{g}.by_engine.{eng}"] = float(n)
        breakdown[f"{g}.false_positives"] = float(t.false_positives)

    return RunResult(
        run_id=new_run_id(),
        label=label,
        run_at=datetime.now(timezone.utc),
        engine=f"{scanner.engine}/{scanner.spacy_model or 'regex'}"
        + ("" if scanner.gazetteer_enabled else "/no-gazetteer"),
        tallies=tallies,
        duration_s=round(time.perf_counter() - t0, 2),
        templates_used=len(templates),
        breakdown=breakdown,
    )


def run_both(
    *,
    corpus: Corpus | None = None,
    max_templates: int | None = None,
    max_names: int | None = None,
    persist: bool = True,
) -> tuple[RunResult, RunResult]:
    """Baseline (NER only) then current (full scanner). Persists both."""
    corpus = corpus or load_corpus()
    current_scanner = get_pii_scanner()
    current_scanner.warm()
    baseline_scanner = PIIScanner(gazetteer_enabled=False, share_presidio_with=current_scanner)

    log.info("fairness: running baseline (NER only) over %d groups", len(corpus.groups))
    baseline = run_configuration(baseline_scanner, corpus, BASELINE_LABEL,
                                 max_templates=max_templates, max_names=max_names)
    log.info("fairness: running current (full scanner)")
    current = run_configuration(current_scanner, corpus, CURRENT_LABEL,
                                max_templates=max_templates, max_names=max_names)
    if persist:
        persist_run(baseline, corpus)
        persist_run(current, corpus)
    return baseline, current


# ---------------------------------------------------------------------------
# Persistence and reporting
# ---------------------------------------------------------------------------


def persist_run(result: RunResult, corpus: Corpus) -> None:
    with session_scope() as s:
        for group, t in result.tallies.items():
            notes = {
                "false_positives": t.false_positives,
                "by_engine": t.by_engine,
                "templates": result.templates_used,
                "duration_s": result.duration_s,
                "corpus_version": corpus.version,
            }
            if group == "indian":
                notes["gazetteer_covered"] = {"n": t.covered_total, "hits": t.covered_hits}
                notes["held_out"] = {"n": t.held_out_total, "hits": t.held_out_hits}
            s.add(FairnessEval(
                run_id=result.run_id,
                run_at=result.run_at,
                label=result.label,
                detector=corpus.detector,
                group=group,
                sample_size=t.total,
                detected=t.hits,
                recall=round(t.recall, 4),
                precision=round(t.precision, 4) if t.precision is not None else None,
                f1=round(t.f1, 4) if t.f1 is not None else None,
                engine=result.engine,
                notes=json.dumps(notes),
            ))
    log.info("fairness: persisted run %s (%s)", result.run_id, result.label)


def _to_run(rows: list[FairnessEval], labels: dict[str, str]) -> FairnessRun:
    groups = [
        FairnessGroupResult(
            group=labels.get(r.group, r.group),
            sample_size=r.sample_size,
            detected=r.detected,
            recall=r.recall,
            precision=r.precision,
            f1=r.f1,
        )
        for r in sorted(rows, key=lambda r: r.group)
    ]
    recalls = [g.recall for g in groups]
    breakdown: dict[str, float] = {}
    for r in rows:
        try:
            n = json.loads(r.notes or "{}")
        except json.JSONDecodeError:
            n = {}
        for eng, cnt in (n.get("by_engine") or {}).items():
            breakdown[f"{r.group}.by_engine.{eng}"] = float(cnt)
        breakdown[f"{r.group}.false_positives"] = float(n.get("false_positives", 0))
        if r.group == "indian":
            for key in ("gazetteer_covered", "held_out"):
                sub = n.get(key) or {}
                if sub.get("n"):
                    breakdown[f"indian.{key}.recall"] = round(sub["hits"] / sub["n"], 4)
                    breakdown[f"indian.{key}.n"] = float(sub["n"])
    return FairnessRun(
        run_id=rows[0].run_id,
        run_at=rows[0].run_at,
        label=rows[0].label,
        detector=rows[0].detector,
        groups=groups,
        best_group_recall=max(recalls) if recalls else None,
        worst_group_recall=min(recalls) if recalls else None,
        recall_gap=round(max(recalls) - min(recalls), 4) if recalls else None,
        notes=rows[0].engine,
        breakdown=breakdown,
    )


def latest_run(label: str) -> list[FairnessEval]:
    with session_scope() as s:
        latest = s.execute(
            select(FairnessEval.run_id)
            .where(FairnessEval.label == label)
            .order_by(FairnessEval.run_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if latest is None:
            return []
        rows = s.execute(select(FairnessEval).where(FairnessEval.run_id == latest)).scalars().all()
        s.expunge_all()
        return list(rows)


def build_report(detector: str = "pii.person") -> FairnessReportResponse:
    corpus = load_corpus()
    b_rows = latest_run(BASELINE_LABEL)
    c_rows = latest_run(CURRENT_LABEL)
    baseline = _to_run(b_rows, corpus.labels) if b_rows else None
    current = _to_run(c_rows, corpus.labels) if c_rows else None
    gap_closed = None
    deltas: dict[str, float] = {}
    if baseline and current:
        if baseline.recall_gap is not None and current.recall_gap is not None:
            gap_closed = round(baseline.recall_gap - current.recall_gap, 4)
        b_by = {g.group: g.recall for g in baseline.groups}
        for g in current.groups:
            if g.group in b_by:
                deltas[g.group] = round(g.recall - b_by[g.group], 4)
        for key in ("indian.gazetteer_covered.recall", "indian.held_out.recall"):
            if key in baseline.breakdown and key in current.breakdown:
                deltas[key] = round(current.breakdown[key] - baseline.breakdown[key], 4)
    return FairnessReportResponse(
        detector=detector,
        baseline=baseline,
        current=current,
        gap_closed=gap_closed,
        deltas=deltas,
        method=METHOD if (baseline or current) else METHOD + " No run recorded yet: POST /api/fairness/run.",
        disclaimer=DISCLAIMER,
    )


def format_table(result: RunResult, corpus: Corpus) -> str:
    lines = [f"{result.label}  ({result.engine}, {result.templates_used} templates, {result.duration_s}s)"]
    lines.append(f"  {'group':12} {'n':>5} {'hits':>5} {'recall':>7} {'prec':>6} {'fp':>4}  engines")
    for g, t in result.tallies.items():
        prec = f"{t.precision:.2f}" if t.precision is not None else "  -"
        eng = ", ".join(f"{k}={v}" for k, v in sorted(t.by_engine.items()))
        lines.append(f"  {corpus.labels.get(g, g):12} {t.total:>5} {t.hits:>5} {t.recall:>7.3f} {prec:>6} {t.false_positives:>4}  {eng}")
    recalls = [t.recall for t in result.tallies.values()]
    lines.append(f"  gap (best - worst recall): {max(recalls) - min(recalls):.3f}")
    ind = result.tallies.get("indian")
    if ind and ind.held_out_total:
        lines.append(
            f"  indian: gazetteer-covered {ind.covered_hits}/{ind.covered_total} "
            f"({ind.covered_hits / ind.covered_total:.3f}), held-out {ind.held_out_hits}/{ind.held_out_total} "
            f"({ind.held_out_hits / ind.held_out_total:.3f})"
        )
    return "\n".join(lines)
