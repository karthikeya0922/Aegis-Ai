"""SQLAlchemy models -- the platform's memory.

Design constraints on our own database (spec s5.5):

  * User identifiers are salted HMACs, never raw. Aegis inspects every prompt
    in an organisation, which makes its own log a surveillance capability;
    the log is pseudonymous by construction.
  * There is no column for prompt text, credentials, passwords, private keys
    or vault contents. A field allowlist in service.py is the second line of
    defence; the schema is the first. Nothing sensitive has anywhere to land.
  * Override tokens are stored hashed. The raw token is minted once, returned
    to the reviewer, and never written down.
  * Every row that carries an estimate carries its basis (Phase 12).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.audit.database import Base

SCHEMA_VERSION = 1


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RequestAudit(Base):
    """One row per inspected request.

    Written in two steps: the Inspector records the decision at /inspect
    time; the Gateway's POST /audit/events later merges provider, token and
    cost fields once the response has completed. Either half alone is a
    valid record, so a Gateway that never posts still leaves the decision
    on file.
    """

    __tablename__ = "request_audit"
    __table_args__ = (
        UniqueConstraint("request_id", name="uq_request_audit_request_id"),
        Index("ix_request_audit_tenant_ts", "tenant_id", "timestamp"),
        Index("ix_request_audit_user_hash", "user_ref_hash"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, default="default")
    user_ref_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    # -- routing / provider (Gateway fills these) --
    provider: Mapped[str | None] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(128))
    routed_complexity: Mapped[str | None] = mapped_column(String(16))

    # -- latency --
    latency_total_ms: Mapped[float | None] = mapped_column(Float)
    latency_inspect_ms: Mapped[float | None] = mapped_column(Float)
    latency_provider_ms: Mapped[float | None] = mapped_column(Float)

    # -- tokens --
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    total_tokens: Mapped[int | None] = mapped_column(Integer)

    # -- cache --
    cache_hit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cache_similarity: Mapped[float | None] = mapped_column(Float)

    # -- detections (Inspector fills these) --
    pii_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pii_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pii_types: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    secret_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    secret_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    secret_types: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    injection_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    injection_score: Mapped[float | None] = mapped_column(Float)
    entropy_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # -- policy --
    policy_action: Mapped[str | None] = mapped_column(String(16))
    policy_version: Mapped[int | None] = mapped_column(Integer)
    policy_profile: Mapped[str | None] = mapped_column(String(64))
    rules_fired: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    block_code: Mapped[str | None] = mapped_column(String(64))
    override_applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # -- failover --
    failover_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    failover_from: Mapped[str | None] = mapped_column(String(64))
    failover_to: Mapped[str | None] = mapped_column(String(64))

    # -- egress --
    egress_flagged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    egress_categories: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    grounding_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    grounding_score: Mapped[float | None] = mapped_column(Float)
    grounding_status: Mapped[str | None] = mapped_column(String(16))

    # -- estimates; the basis lives in config and is reported alongside --
    estimated_cost_usd: Mapped[float | None] = mapped_column(Float)
    estimated_savings_usd: Mapped[float | None] = mapped_column(Float)
    estimated_energy_wh: Mapped[float | None] = mapped_column(Float)
    estimated_co2_g: Mapped[float | None] = mapped_column(Float)

    # -- oversight --
    review_id: Mapped[str | None] = mapped_column(String(64))

    # -- pipeline timings, for overhead metrics --
    stage_timings_ms: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=SCHEMA_VERSION)
    gateway_finalized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ReviewRequest(Base):
    """A human-review appeal of an automated block (Requirement 1)."""

    __tablename__ = "review_request"
    __table_args__ = (
        Index("ix_review_request_status", "status"),
        Index("ix_review_request_request_id", "request_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, default="default")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    requester_ref_hash: Mapped[str | None] = mapped_column(String(64))
    original_decision: Mapped[str] = mapped_column(String(16), nullable=False)
    rule_fired: Mapped[str | None] = mapped_column(String(128))
    user_justification: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    reviewer_ref_hash: Mapped[str | None] = mapped_column(String(64))
    reviewer_note: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # The raw token is never stored. Verification hashes the presented token
    # and compares.
    override_token_hash: Mapped[str | None] = mapped_column(String(64))
    override_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    override_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PolicyVersion(Base):
    """Every policy change is an immutable row (Requirement 7)."""

    __tablename__ = "policy_version"
    __table_args__ = (UniqueConstraint("version", name="uq_policy_version_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    yaml_body: Mapped[str] = mapped_column(Text, nullable=False)
    author_ref_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    diff_summary: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)


class FairnessEval(Base):
    """One row per (run, group): measured detector recall (Requirement 5)."""

    __tablename__ = "fairness_eval"
    __table_args__ = (Index("ix_fairness_eval_run", "run_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    label: Mapped[str] = mapped_column(String(64), nullable=False)
    detector: Mapped[str] = mapped_column(String(64), nullable=False)
    group: Mapped[str] = mapped_column(String(64), nullable=False)
    sample_size: Mapped[int] = mapped_column(Integer, nullable=False)
    detected: Mapped[int] = mapped_column(Integer, nullable=False)
    recall: Mapped[float] = mapped_column(Float, nullable=False)
    precision: Mapped[float | None] = mapped_column(Float)
    f1: Mapped[float | None] = mapped_column(Float)
    engine: Mapped[str | None] = mapped_column(String(64))
    notes: Mapped[str | None] = mapped_column(Text)


# Columns that must never exist. Checked by tests against every table so a
# future migration cannot quietly add one.
FORBIDDEN_COLUMN_NAMES = frozenset({
    "prompt", "prompt_text", "content", "messages", "text", "raw_text",
    "api_key", "password", "secret", "token", "override_token", "private_key",
    "vault", "user_ref", "user_id", "email", "username",
})
