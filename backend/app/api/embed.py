"""Embedding endpoint. Real as of Phase 9.

The Inspector computes vectors; the Gateway owns the Redis vector index and
the cosine search. Vectors are L2-normalised so cosine is a plain dot
product. The response names the engine and flags degradation, so a Gateway
can refuse to build a semantic index on hash-fallback vectors.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.cache.embeddings import MAX_TEXTS, get_embedding_service
from app.contracts.embed import EmbedRequest, EmbedResponse

router = APIRouter(tags=["embeddings"])


@router.post(
    "/embed",
    response_model=EmbedResponse,
    summary="Embed text for the semantic cache",
    description=(
        "Returns L2-normalised vectors from the configured sentence-transformer "
        "(all-MiniLM-L6-v2 by default, dim 384). Assert `dim` against your Redis "
        "index on startup and check `engine`: `hash-fallback` means the model "
        "was unavailable and the vectors have no semantic structure -- exact "
        "matches still work, near matches do not.\n\n"
        "Measured on this model: 'Is this drug safe during pregnancy?' and "
        "'...not safe...' score cosine 0.989. Similarity cannot see negation; "
        "honour `cache.semantic_guards` from /inspect before serving a hit."
    ),
)
async def embed(req: EmbedRequest) -> EmbedResponse:
    if len(req.texts) > MAX_TEXTS:
        raise HTTPException(status_code=413, detail=f"at most {MAX_TEXTS} texts per call")
    svc = get_embedding_service()
    if req.model and req.model != svc.model_name:
        raise HTTPException(
            status_code=400,
            detail=f"this deployment serves {svc.model_name}; per-request model selection is not supported",
        )
    r = svc.embed(req.texts, normalize=req.normalize)
    return EmbedResponse(
        model=r.model, dim=r.dim, normalized=r.normalized, vectors=r.vectors,
        duration_ms=r.duration_ms, engine=r.engine, degraded=r.degraded,
    )
