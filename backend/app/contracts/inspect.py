"""Contract for POST /inspect -- the ingress decision endpoint."""

from __future__ import annotations

from pydantic import Field

from app.contracts.common import (
    BlockReason,
    Complexity,
    Decision,
    Detection,
    EntropyFinding,
    InjectionFinding,
    Message,
    PipelineStage,
    StrictModel,
)


class InspectOptions(StrictModel):
    return_vault: bool = True
    return_explanation: bool = True


class InspectRequest(StrictModel):
    request_id: str
    tenant_id: str = "default"
    user_ref: str | None = None
    messages: list[Message]
    mode: str | None = None
    policy_profile: str | None = None
    locale_hints: list[str] = Field(default_factory=list)
    override_token: str | None = None
    options: InspectOptions = Field(default_factory=InspectOptions)


class DetectionBundle(StrictModel):
    pii: list[Detection] = Field(default_factory=list)
    secrets: list[Detection] = Field(default_factory=list)
    entropy: list[EntropyFinding] = Field(default_factory=list)
    injection: InjectionFinding = Field(default_factory=InjectionFinding)


class DetectionCounts(StrictModel):
    pii: int = 0
    secrets: int = 0
    entropy: int = 0
    injection: int = 0


class VaultPolicy(StrictModel):
    rehydrate: list[str] = Field(default_factory=lambda: ["PII"])
    never_rehydrate: list[str] = Field(default_factory=lambda: ["SECRET"])
    ttl_seconds: int = 300


class SemanticGuards(StrictModel):
    """Markers the Gateway must match exactly before serving a cache hit.

    Cosine similarity handles negation and numeric swaps poorly: "is X safe
    during pregnancy" and "is X unsafe during pregnancy" embed very close
    together. Serving one from the other is a safety failure, not a perf win.
    """

    negations: list[str] = Field(default_factory=list)
    numbers: list[str] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)


class CacheHint(StrictModel):
    """Whether the Gateway may cache this request, and the guards to match.

    `reason` vocabulary when `cacheable` is false:
        blocked                 -- the request was blocked; nothing to cache
        credential_present      -- a secret was detected
        personal_data_present   -- PII was detected and AEGIS_CACHE_ALLOW_PII is off
    and when true:
        null                             -- ordinary cacheable request
        personal_data_allowed_by_config  -- PII present but caching allowed
    """

    cacheable: bool = True
    reason: str | None = None
    semantic_guards: SemanticGuards = Field(default_factory=SemanticGuards)


class RoutingHint(StrictModel):
    complexity: Complexity = Complexity.MEDIUM
    reasons: list[str] = Field(default_factory=list)


class InspectResponse(StrictModel):
    request_id: str
    policy_version: int = 1
    decision: Decision
    block_reason: BlockReason | None = None

    messages: list[Message]

    detections: DetectionBundle = Field(default_factory=DetectionBundle)
    counts: DetectionCounts = Field(default_factory=DetectionCounts)

    vault: dict[str, str] = Field(default_factory=dict)
    vault_policy: VaultPolicy = Field(default_factory=VaultPolicy)

    cache: CacheHint = Field(default_factory=CacheHint)
    routing_hint: RoutingHint = Field(default_factory=RoutingHint)

    explanation: str = ""
    override_applied: bool = False

    pipeline: list[PipelineStage] = Field(default_factory=list)
    total_duration_ms: float = Field(default=0.0, ge=0)
