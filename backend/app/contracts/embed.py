"""Contract for POST /embed -- vectors for Person 2's Redis semantic cache."""

from __future__ import annotations

from pydantic import Field

from app.contracts.common import StrictModel


class EmbedRequest(StrictModel):
    texts: list[str] = Field(min_length=1)
    model: str | None = None
    normalize: bool = True


class EmbedResponse(StrictModel):
    model: str
    dim: int
    normalized: bool
    vectors: list[list[float]]
    duration_ms: float = Field(ge=0)
