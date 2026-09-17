"""Phase 13 -- the fairness harness.

These test the harness's *correctness*, not a target recall. A fairness
harness that asserts "recall must be >= X" would fail the moment it did its
job and found a gap; the point is that the numbers are measured, persisted,
and reported honestly -- including a zero gap-closed when the worst-served
group did not change.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.audit.database import session_scope
from app.audit.models import FairnessEval
from app.contracts.common import Detection, DetectionCategory, PolicyAction
from app.fairness import harness
from app.fairness.harness import (
    BASELINE_LABEL,
    CURRENT_LABEL,
    GroupTally,
    load_corpus,
    run_both,
    score_sample,
)
from app.security.pii_scanner import PIIScanner, get_pii_scanner


def _wipe():
    with session_scope() as s:
        s.query(FairnessEval).delete()


@pytest.fixture(scope="module", autouse=True)
def _clean_module():
    """Once per module. quick_runs persists rows that later tests read."""
    _wipe()
    yield


@pytest.fixture(scope="module")
def corpus():
    return load_corpus()


# ---------------------------------------------------------------------------
# Corpus integrity
# ---------------------------------------------------------------------------


def test_corpus_has_five_groups_of_sixty(corpus):
    assert set(corpus.groups) == {"indian", "anglo", "arabic", "east_asian", "african"}
    for g, names in corpus.groups.items():
        assert len(names) >= 60, g
        assert len(set(names)) == len(names), f"duplicate names in {g}"


def test_templates_are_identical_across_groups(corpus):
    """Same sentences for every group -- that is what makes the comparison fair."""
    assert len(corpus.templates) >= 4
    for t in corpus.templates:
        assert t.count("{name}") == 1


def test_indian_corpus_is_not_just_the_gazetteer(corpus):
    """Measuring the gazetteer only on names it contains would be circular."""
    india = get_pii_scanner()._india  # noqa: SLF001
    held_out = [n for n in corpus.groups["indian"] if not india.covers(n)]
    covered = [n for n in corpus.groups["indian"] if india.covers(n)]
    assert len(held_out) >= 20, "need a meaningful held-out set"
    assert len(covered) >= 20, "need a meaningful covered set"


def test_corpus_includes_hyphenated_names(corpus):
    """Kept on purpose so the harness surfaces the hyphen weakness."""
    assert any("-" in n for n in corpus.groups["east_asian"])


def test_bad_template_is_rejected(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("version: 1\ntemplates: ['no slot here']\ngroups: {a: {names: [X Y]}}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one"):
        load_corpus(f)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


class _FakeScanner:
    """Returns canned PERSON detections so scoring can be tested exactly."""

    def __init__(self, spans):
        self.spans = spans

    def scan(self, text, message_index=0):
        dets = [
            Detection(type="PERSON", category=DetectionCategory.PII, placeholder="[PERSON_1]",
                      confidence=0.9, start=s, end=e, recognizer=r, action=PolicyAction.ALLOW)
            for (s, e, r) in self.spans
        ]
        return dets, {}


def test_score_full_cover_is_a_hit():
    sentence = "Contact Priya Ramaswamy about the invoice."
    s, e = 8, 8 + len("Priya Ramaswamy")
    hit, engine, fps = score_sample(_FakeScanner([(s, e, "india.name_gazetteer")]), sentence, "Priya Ramaswamy")
    assert hit and engine == "india" and fps == 0


def test_score_partial_overlap_is_a_miss_not_a_false_positive():
    """Surname only: redaction would leave the given name visible."""
    sentence = "Contact Priya Ramaswamy about the invoice."
    s = sentence.index("Ramaswamy")
    hit, _, fps = score_sample(_FakeScanner([(s, s + 9, "presidio.x")]), sentence, "Priya Ramaswamy")
    assert not hit and fps == 0


def test_score_detection_elsewhere_is_a_false_positive():
    sentence = "Please forward this to Priya Ramaswamy by Friday."
    fri = sentence.index("Friday")
    hit, _, fps = score_sample(_FakeScanner([(fri, fri + 6, "presidio.x")]), sentence, "Priya Ramaswamy")
    assert not hit and fps == 1


def test_score_prefers_first_covering_engine():
    sentence = "Contact Priya Ramaswamy now."
    s, e = 8, 8 + 15
    hit, engine, _ = score_sample(
        _FakeScanner([(s, e, "presidio.SpacyRecognizer"), (s, e, "india.name_gazetteer")]),
        sentence, "Priya Ramaswamy",
    )
    assert hit and engine == "presidio"


def test_tally_metrics():
    t = GroupTally(total=10, hits=8, false_positives=2)
    assert t.recall == 0.8
    assert t.precision == 0.8
    assert round(t.f1, 4) == 0.8
    assert GroupTally().recall == 0.0 and GroupTally().precision is None


# ---------------------------------------------------------------------------
# Runs -- small subset so the suite stays fast
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def quick_runs(corpus):
    return run_both(corpus=corpus, max_templates=2, max_names=6, persist=True)


def test_baseline_really_disables_the_gazetteer(quick_runs):
    baseline, current = quick_runs
    assert "no-gazetteer" in baseline.engine
    assert "no-gazetteer" not in current.engine
    assert "india" not in baseline.tallies["indian"].by_engine
    # and the gazetteer participated in the current run
    assert current.tallies["indian"].by_engine.get("india", 0) >= 1


def test_baseline_shares_the_loaded_model(quick_runs):
    """The baseline scanner must not have loaded spaCy a second time."""
    cur = get_pii_scanner()
    base = PIIScanner(gazetteer_enabled=False, share_presidio_with=cur)
    assert base._presidio is cur._presidio  # noqa: SLF001


def test_every_group_is_tallied(quick_runs, corpus):
    for run in quick_runs:
        assert set(run.tallies) == set(corpus.groups)
        for t in run.tallies.values():
            assert t.total == 2 * 6
            assert 0 <= t.hits <= t.total


def test_indian_split_sums_to_total(quick_runs):
    for run in quick_runs:
        t = run.tallies["indian"]
        assert t.covered_total + t.held_out_total == t.total
        assert t.covered_hits + t.held_out_hits == t.hits


def test_runs_are_persisted_one_row_per_group(quick_runs, corpus):
    with session_scope() as s:
        rows = s.execute(select(FairnessEval)).scalars().all()
        assert len(rows) == 2 * len(corpus.groups)
        labels = {r.label for r in rows}
        assert labels == {BASELINE_LABEL, CURRENT_LABEL}
        indian = next(r for r in rows if r.label == CURRENT_LABEL and r.group == "indian")
        notes = json.loads(indian.notes)
        assert "held_out" in notes and "gazetteer_covered" in notes


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def test_report_is_null_before_any_run(monkeypatch):
    monkeypatch.setattr(harness, "latest_run", lambda label: [])
    r = harness.build_report()
    assert r.baseline is None and r.current is None and r.gap_closed is None
    assert "No run recorded" in r.method
    assert "not a representative population sample" in r.disclaimer


def test_report_after_run(quick_runs, corpus):
    r = harness.build_report()
    assert r.baseline is not None and r.current is not None
    assert len(r.current.groups) == len(corpus.groups)
    assert r.current.recall_gap == round(r.current.best_group_recall - r.current.worst_group_recall, 4)
    assert r.gap_closed == round(r.baseline.recall_gap - r.current.recall_gap, 4)
    # deltas cover every group and the Indian split
    assert set(r.deltas) >= set(corpus.labels.values())
    # The Indian split is reported for whichever subsets the run contained.
    _, current = quick_runs
    ind = current.tallies["indian"]
    if ind.covered_total:
        assert "indian.gazetteer_covered.recall" in r.current.breakdown
    if ind.held_out_total:
        assert "indian.held_out.recall" in r.current.breakdown
    assert ind.covered_total or ind.held_out_total
    assert r.disclaimer


def test_report_uses_the_latest_run_per_label(corpus):
    run_both(corpus=corpus, max_templates=1, max_names=2, persist=True)
    first = harness.build_report().current.run_id
    run_both(corpus=corpus, max_templates=1, max_names=2, persist=True)
    second = harness.build_report().current.run_id
    assert first != second


def test_report_does_not_hide_a_zero_gap_closed(quick_runs):
    """If the worst-served group is unchanged, gap_closed is 0.0 -- reported,
    not masked. That is a finding about where the next fix belongs."""
    r = harness.build_report()
    assert isinstance(r.gap_closed, float)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def test_api_report_and_run():
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    _wipe()
    before = client.get("/api/fairness/report").json()
    assert before["current"] is None

    r = client.post("/api/fairness/run?max_templates=1&max_names=3")
    assert r.status_code == 200
    body = r.json()
    assert body["current"]["groups"] and body["baseline"]["groups"]
    assert "deltas" in body and "disclaimer" in body

    after = client.get("/api/fairness/report").json()
    assert after["current"]["run_id"] == body["current"]["run_id"]
