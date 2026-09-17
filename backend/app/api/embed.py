"""Embedding endpoint.

The Inspector computes vectors; Person 2's Gateway owns the Redis vector index
and the cosine search. Keeping the model on this side means only one service
loads sentence-transformers.

Phase 0 returns deterministic pseudo-vectors of the correct dimension so the
Gateway can build and exercise its Redis index before the real model lands in
Phase 9. `deterministic_stub` in the response marks them as not real.
"""

from __future__ import annotations

import hashlib
import math
import time

from fastapi import APIRouter

from app.config import settings
from app.contracts.embed import EmbedRequest, EmbedResponse

router = APIRouter(tags=["embeddings"])


def _pseudo_vector(text: str, dim: int, normalize: bool) -> list[float]:
    """Deterministic hash-derived vector.

    Same text always yields the same vector, so an exact-match cache hit is
    demonstrable in Phase 0. Semantically unrelated text yields an unrelated
    vector -- but these carry no real semantic structure, so *near*-match
    behaviour only becomes meaningful in Phase 9.
    """
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


@router.post(
    "/embed",
    response_model=EmbedResponse,
    summary="Embed text for the semantic cache",
    description=(
        "Returns L2-normalised vectors so the Gateway's cosine search is a "
        "plain dot product. Assert `dim` against your Redis index on startup."
    ),
)
async def embed(req: EmbedRequest) -> EmbedResponse:
    started = time.perf_counter()
    model = req.model or settings.embedding_model
    dim = settings.embedding_dim
    vectors = [_pseudo_vector(t, dim, req.normalize) for t in req.texts]
    return EmbedResponse(
        model=f"{model} (phase0-deterministic-stub)",
        dim=dim,
        normalized=req.normalize,
        vectors=vectors,
        duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
    )
