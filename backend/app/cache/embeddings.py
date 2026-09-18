"""Embeddings for the Gateway's semantic cache.

The Inspector computes vectors; the Gateway owns the Redis vector index and
the cosine search. Keeping the model on this side means only one service
loads sentence-transformers.

Engine selection, in order:

  * sentence-transformers with the configured model (all-MiniLM-L6-v2 by
    default), lazy-loaded once, warmed at startup. Vectors are L2-normalised
    so the Gateway's cosine similarity is a plain dot product.
  * if the package or the weights are unavailable: a deterministic
    hash-derived vector of the configured dimension. Same text -> same
    vector, so an exact-match cache still works, but the vectors carry no
    semantic structure and NEAR matches are meaningless. The response says
    so (`engine: hash-fallback`, `degraded: true`) and /api/health reports it.

Why the guards in routing.yaml matter, measured on this model: "Is this
drug safe during pregnancy?" vs "...not safe..." scores cosine 0.989 --
above a 0.92 cache threshold and higher than a genuine paraphrase pair
(0.918). Cosine similarity cannot see negation. The Gateway must refuse a
hit unless the semantic guards match, whatever the similarity says.
"""

from __future__ import annotations

import hashlib
import math
import os
import threading
import time
from dataclasses import dataclass
from functools import lru_cache

from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)

MAX_TEXTS = 256
MAX_CHARS = 8_000

os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")


@dataclass
class EmbedResult:
    vectors: list[list[float]]
    model: str
    dim: int
    normalized: bool
    engine: str  # "sentence-transformers" | "hash-fallback"
    degraded: bool
    duration_ms: float


def _pseudo_vector(text: str, dim: int, normalize: bool) -> list[float]:
    """Deterministic hash-derived vector. Fallback only -- no semantics."""
    seed = hashlib.sha256(text.encode("utf-8")).digest()
    vals: list[float] = []
    counter = 0
    while len(vals) < dim:
        block = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        for i in range(0, len(block), 2):
            if len(vals) >= dim:
                break
            raw = int.from_bytes(block[i : i + 2], "big")
            vals.append((raw / 32767.5) - 1.0)
        counter += 1
    if normalize:
        norm = math.sqrt(sum(v * v for v in vals)) or 1.0
        vals = [v / norm for v in vals]
    return vals


class EmbeddingService:
    def __init__(self, model_name: str | None = None) -> None:
        self.model_name = model_name or settings.embedding_model
        self._model = None
        self._attempted = False
        self._lock = threading.Lock()
        self.degraded_reason: str | None = None
        self.dim: int = settings.embedding_dim

    # -- loading ----------------------------------------------------------------

    def _try_load(self) -> None:
        if self._attempted:
            return
        with self._lock:
            if self._attempted:
                return
            self._attempted = True
            t0 = time.perf_counter()
            try:
                from sentence_transformers import SentenceTransformer  # noqa: WPS433 - optional

                self._model = SentenceTransformer(self.model_name, device="cpu")
                actual = int(self._model.get_sentence_embedding_dimension())
                if actual != settings.embedding_dim:
                    log.warning(
                        "embeddings: model %s has dim %d, config says %d; reporting %d",
                        self.model_name, actual, settings.embedding_dim, actual,
                    )
                self.dim = actual
                log.info("embeddings: %s ready (dim=%d) in %.1fs",
                         self.model_name, self.dim, time.perf_counter() - t0)
            except ImportError as exc:
                self.degraded_reason = f"sentence-transformers not installed ({exc.name})"
            except Exception as exc:  # noqa: BLE001 - weights missing, offline, etc.
                self.degraded_reason = f"{type(exc).__name__}: {str(exc)[:120]}"
            if self.degraded_reason:
                log.warning("embeddings DEGRADED to hash fallback: %s", self.degraded_reason)

    def warm(self) -> None:
        self._try_load()
        if self._model is not None:
            self._model.encode(["warm-up"], normalize_embeddings=True)

    @property
    def degraded(self) -> bool:
        self._try_load()
        return self._model is None

    @property
    def engine(self) -> str:
        return "hash-fallback" if self.degraded else "sentence-transformers"

    # -- embedding ----------------------------------------------------------------

    def embed(self, texts: list[str], *, normalize: bool = True) -> EmbedResult:
        if not texts:
            raise ValueError("texts must not be empty")
        if len(texts) > MAX_TEXTS:
            raise ValueError(f"at most {MAX_TEXTS} texts per call")
        clipped = [t[:MAX_CHARS] for t in texts]

        t0 = time.perf_counter()
        self._try_load()
        if self._model is None:
            vectors = [_pseudo_vector(t, self.dim, normalize) for t in clipped]
            model_label = f"{self.model_name} (unavailable: hash fallback)"
        else:
            arr = self._model.encode(
                clipped, normalize_embeddings=normalize, convert_to_numpy=True, batch_size=64,
            )
            vectors = [[float(x) for x in row] for row in arr]
            model_label = self.model_name

        return EmbedResult(
            vectors=vectors,
            model=model_label,
            dim=self.dim,
            normalized=normalize,
            engine=self.engine,
            degraded=self.degraded,
            duration_ms=round((time.perf_counter() - t0) * 1000.0, 3),
        )

    def health(self) -> dict:
        self._try_load()
        return {
            "engine": self.engine,
            "degraded": self.degraded,
            "degraded_reason": self.degraded_reason,
            "model": self.model_name,
            "dim": self.dim,
        }


@lru_cache
def get_embedding_service() -> EmbeddingService:
    return EmbeddingService()
