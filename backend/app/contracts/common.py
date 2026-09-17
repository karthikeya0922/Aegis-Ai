"""Shared contract primitives.

These types are the seam between Person 1 (Inspector) and Person 2 (Gateway).
Changing anything here is a breaking change and must be agreed by both.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Base model: rejects unknown fields so contract drift fails loudly."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Decision(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    WARN = "WARN"
    BLOCK = "BLOCK"


class PolicyAction(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    WARN = "warn"
    BLOCK = "block"


class StageStatus(str, Enum):
    SUCCESS = "success"
    WARNING = "warning"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    ERROR = "error"
    HIT = "hit"
    MISS = "miss"


class Complexity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EgressAction(str, Enum):
    PASS = "PASS"
    ANNOTATE = "ANNOTATE"
    REPLACE = "REPLACE"


class GroundingStatus(str, Enum):
    GROUNDED = "GROUNDED"
    REVIEW = "REVIEW"
    UNGROUNDED = "UNGROUNDED"
    SKIPPED = "SKIPPED"


class ReviewStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"


class DetectionCategory(str, Enum):
    PII = "PII"
    SECRET = "SECRET"
    ENTROPY = "ENTROPY"
    INJECTION = "INJECTION"


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------


class Message(StrictModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str
    name: str | None = None


class PipelineStage(StrictModel):
    """One executed stage. `duration_ms` is always measured, never estimated."""

    stage: str
    status: StageStatus
    duration_ms: float = Field(ge=0)
    detail: str | None = None


class Detection(StrictModel):
    """A single finding.

    Deliberately carries no raw matched value. The original text lives only in
    the vault map, which the Gateway treats as secret-grade and never logs.
    """

    type: str
    category: DetectionCategory
    placeholder: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    message_index: int = Field(default=0, ge=0)
    recognizer: str | None = None
    pattern: str | None = None
    action: PolicyAction = PolicyAction.ALLOW


class EntropyFinding(StrictModel):
    type: Literal["HIGH_ENTROPY_STRING"] = "HIGH_ENTROPY_STRING"
    category: DetectionCategory = DetectionCategory.ENTROPY
    entropy: float
    length: int
    confidence: float = Field(ge=0.0, le=1.0)
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    message_index: int = Field(default=0, ge=0)
    action: PolicyAction = PolicyAction.WARN


class InjectionFinding(StrictModel):
    detected: bool = False
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_rules: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)


class BlockReason(StrictModel):
    code: str
    message: str
    http_status: int = 400
    rule_id: str | None = None
    appealable: bool = False


class ErrorEnvelope(BaseModel):
    """Safe error response. Never carries stack traces or raw input."""

    model_config = ConfigDict(extra="forbid")

    error: dict[str, Any]
