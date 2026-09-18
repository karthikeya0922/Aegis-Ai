"""Phase 9 -- embeddings.

Engine-aware, like the PII tests: determinism, dimension and normalisation
hold in both modes; the semantic assertions run only with the real model
and are skipped -- not failed -- without it. A separate test forces the
fallback and checks it is reported, never hidden.
"""

from __future__ import annotations

import math

import pytest

from app.cache import embeddings as mod
from app.cache.embeddings import EmbeddingService, get_embedding_service


@pytest.fixture(scope="module")
def svc() -> EmbeddingService:
    s = get_embedding_service()
    s.warm()
    return s


needs_model = pytest.mark.skipif(
    get_embedding_service().degraded, reason="sentence-transformers model unavailable"
)


def cos(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def norm(v: list[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


# ---------------------------------------------------------------------------
# Hold in both engines
# ---------------------------------------------------------------------------


def test_dimension_and_shape(svc):
    r = svc.embed(["a", "b", "c"])
    assert r.dim == svc.dim and len(r.vectors) == 3
    assert all(len(v) == r.dim for v in r.vectors)


def test_deterministic(svc):
    a = svc.embed(["What is the capital of France?"]).vectors[0]
    b = svc.embed(["What is the capital of France?"]).vectors[0]
    assert a == pytest.approx(b, abs=1e-6)


def test_batch_equals_single(svc):
    texts = ["one", "two", "three"]
    batch = svc.embed(texts).vectors
    singles = [svc.embed([t]).vectors[0] for t in texts]
    for x, y in zip(batch, singles):
        assert x == pytest.approx(y, abs=1e-5)


def test_normalised_by_default(svc):
    for v in svc.embed(["hello world", "another sentence here"]).vectors:
        assert norm(v) == pytest.approx(1.0, abs=1e-5)


def test_unnormalised_when_asked(svc):
    r = svc.embed(["hello world"], normalize=False)
    assert r.normalized is False


def test_response_names_engine_and_model(svc):
    r = svc.embed(["x"])
    assert r.engine in {"sentence-transformers", "hash-fallback"}
    assert r.degraded is (r.engine == "hash-fallback")
    assert r.model and r.duration_ms >= 0


def test_limits(svc):
    with pytest.raises(ValueError):
        svc.embed([])
    with pytest.raises(ValueError):
        svc.embed(["x"] * (mod.MAX_TEXTS + 1))
    # over-long text is clipped, not rejected
    r = svc.embed(["y" * (mod.MAX_CHARS * 2)])
    assert len(r.vectors) == 1


# ---------------------------------------------------------------------------
# Real model only
# ---------------------------------------------------------------------------


@needs_model
def test_paraphrase_is_close_and_unrelated_is_far(svc):
    v = svc.embed(["What is the capital of France?", "France's capital city?", "Recipe for pancakes"]).vectors
    assert cos(v[0], v[1]) > 0.8
    assert cos(v[0], v[2]) < 0.4


@needs_model
def test_negation_is_indistinguishable_by_cosine(svc):
    """The documented reason semantic guards exist: cosine cannot see 'not'.

    If a future model makes this pair distinguishable, this test fails and
    the guard rationale in routing.yaml should be revisited -- not removed,
    since numbers and entities have the same problem.
    """
    v = svc.embed(["Is this drug safe during pregnancy?", "Is this drug not safe during pregnancy?"]).vectors
    assert cos(v[0], v[1]) > 0.92, "negation pair would pass the default cache threshold"


@needs_model
def test_real_engine_reports_itself(svc):
    r = svc.embed(["x"])
    assert r.engine == "sentence-transformers" and r.degraded is False
    assert r.model == svc.model_name and r.dim == 384


# ---------------------------------------------------------------------------
# Degradation is honest
# ---------------------------------------------------------------------------


def test_fallback_is_reported_not_hidden(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_st(name, *a, **k):
        if name.startswith("sentence_transformers"):
            raise ImportError("sentence_transformers", name="sentence_transformers")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_st)
    s = EmbeddingService()
    r = s.embed(["hello", "hello", "world"])
    assert s.degraded and r.degraded and r.engine == "hash-fallback"
    assert "not installed" in (s.degraded_reason or "")
    assert "hash fallback" in r.model
    # deterministic and normalised, but semantically empty
    assert r.vectors[0] == r.vectors[1] and r.vectors[0] != r.vectors[2]
    assert norm(r.vectors[0]) == pytest.approx(1.0, abs=1e-6)
    assert len(r.vectors[0]) == s.dim


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def test_api_embed():
    from fastapi.testclient import TestClient

    from app.main import app

    c = TestClient(app)
    r = c.post("/embed", json={"texts": ["hello", "hello"]})
    assert r.status_code == 200
    body = r.json()
    assert body["dim"] == 384 and len(body["vectors"]) == 2
    assert body["vectors"][0] == body["vectors"][1]
    assert body["engine"] in {"sentence-transformers", "hash-fallback"}
    assert "degraded" in body

    too_many = c.post("/embed", json={"texts": ["x"] * (mod.MAX_TEXTS + 1)})
    assert too_many.status_code == 413
    wrong_model = c.post("/embed", json={"texts": ["x"], "model": "some-other-model"})
    assert wrong_model.status_code == 400
