"""Audit write path and reads.

Two writers, one row:

  * `record_inspection` -- called after /inspect. Records the decision,
    detections, policy and stage timings. Fire-and-forget: a failure here
    is logged and counted, never surfaced to the caller.
  * `upsert_event` -- POST /audit/events from the Gateway. Merges provider,
    token, cache, cost and egress fields into the same row once the
    response has completed. Idempotent on request_id.

Field allowlist: both writers map named fields explicitly. There is no
`**kwargs` path and no `setattr` loop over incoming data, so a field that
is not in the mapping cannot reach the table -- regardless of what the
contract, or a future contract, accepts.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select

from app.audit.database import session_scope
from app.audit.models import RequestAudit
from app.config import settings
from app.contracts.audit import AuditEventRecord, AuditEventRequest
from app.contracts.egress import EgressResponse
from app.contracts.common import DetectionCategory
from app.contracts.inspect import InspectRequest, InspectResponse
from app.utils.ids import hash_user_ref
from app.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class WriteStats:
    inspections_recorded: int = 0
    events_upserted: int = 0
    failures: int = 0


_stats = WriteStats()
_stats_lock = threading.Lock()


def stats() -> WriteStats:
    return _stats


def _bump(field: str) -> None:
    with _stats_lock:
        setattr(_stats, field, getattr(_stats, field) + 1)


def token_hash(token: str) -> str:
    """Override tokens are stored hashed; the raw value is never written."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------


def record_inspection(req: InspectRequest, res: InspectResponse) -> bool:
    """Persist the Inspector's half of the row. Never raises."""
    try:
        with session_scope() as s:
            row = s.execute(
                select(RequestAudit).where(RequestAudit.request_id == req.request_id)
            ).scalar_one_or_none()
            if row is None:
                row = RequestAudit(request_id=req.request_id)
                s.add(row)

            pii = res.detections.pii
            secrets = res.detections.secrets

            row.tenant_id = req.tenant_id
            row.user_ref_hash = hash_user_ref(req.user_ref)
            row.timestamp = row.timestamp or datetime.now(timezone.utc)
            row.routed_complexity = res.routing_hint.complexity.value
            row.latency_inspect_ms = res.total_duration_ms

            row.pii_detected = bool(pii)
            row.pii_count = len(pii)
            row.pii_types = sorted({d.type for d in pii})
            row.secret_detected = bool(secrets)
            row.secret_count = len(secrets)
            row.secret_types = sorted({d.type for d in secrets})
            row.injection_detected = res.detections.injection.detected
            row.injection_score = res.detections.injection.score
            row.entropy_count = len(res.detections.entropy)

            row.policy_action = res.decision.value
            row.policy_version = res.policy_version
            row.policy_profile = _profile_from_pipeline(res)
            row.rules_fired = _rules_from_pipeline(res)
            row.block_code = res.block_reason.code if res.block_reason else None
            row.override_applied = res.override_applied

            row.stage_timings_ms = {st.stage: st.duration_ms for st in res.pipeline}
        _bump("inspections_recorded")
        return True
    except Exception as exc:  # noqa: BLE001 - audit must never fail the request
        _bump("failures")
        log.error("audit: failed to record inspection %s: %s", req.request_id, type(exc).__name__)
        return False


def upsert_event(ev: AuditEventRequest) -> tuple[bool, bool]:
    """Merge the Gateway's half. Returns (stored, was_duplicate_finalize)."""
    try:
        with session_scope() as s:
            row = s.execute(
                select(RequestAudit).where(RequestAudit.request_id == ev.request_id)
            ).scalar_one_or_none()
            duplicate = row is not None and row.gateway_finalized
            if row is None:
                row = RequestAudit(request_id=ev.request_id, tenant_id=ev.tenant_id)
                s.add(row)

            if ev.user_ref:
                row.user_ref_hash = hash_user_ref(ev.user_ref)
            if ev.tenant_id:
                row.tenant_id = ev.tenant_id

            # Gateway-owned fields: set when provided, never cleared by None.
            for src, dst in (
                ("provider", "provider"), ("model", "model"),
                ("routed_complexity", "routed_complexity"),
                ("latency_total_ms", "latency_total_ms"),
                ("latency_inspect_ms", "latency_inspect_ms"),
                ("latency_provider_ms", "latency_provider_ms"),
                ("input_tokens", "input_tokens"), ("output_tokens", "output_tokens"),
                ("total_tokens", "total_tokens"),
                ("cache_similarity", "cache_similarity"),
                ("injection_score", "injection_score"),
                ("policy_version", "policy_version"),
                ("failover_from", "failover_from"), ("failover_to", "failover_to"),
                ("grounding_score", "grounding_score"),
                ("estimated_cost_usd", "estimated_cost_usd"),
                ("estimated_savings_usd", "estimated_savings_usd"),
                ("estimated_energy_wh", "estimated_energy_wh"),
                ("estimated_co2_g", "estimated_co2_g"),
                ("review_id", "review_id"),
            ):
                val = getattr(ev, src)
                if val is not None:
                    setattr(row, dst, val)

            # Booleans and lists: the Gateway's value is authoritative when it
            # has more information than the Inspector had.
            row.cache_hit = ev.cache_hit or row.cache_hit
            row.failover_used = ev.failover_used or row.failover_used
            row.egress_flagged = ev.egress_flagged or row.egress_flagged
            if ev.egress_categories:
                row.egress_categories = list(ev.egress_categories)
            row.grounding_enabled = ev.grounding_enabled or row.grounding_enabled
            if ev.grounding_status is not None:
                row.grounding_status = ev.grounding_status.value
            if ev.policy_action is not None:
                row.policy_action = ev.policy_action.value
            if ev.rules_fired:
                row.rules_fired = sorted(set(row.rules_fired or []) | set(ev.rules_fired))
            if ev.pii_count or ev.pii_detected:
                row.pii_detected = True
                row.pii_count = max(row.pii_count or 0, ev.pii_count)
                if ev.pii_types:
                    row.pii_types = sorted(set(row.pii_types or []) | set(ev.pii_types))
            if ev.secret_count or ev.secret_detected:
                row.secret_detected = True
                row.secret_count = max(row.secret_count or 0, ev.secret_count)
                if ev.secret_types:
                    row.secret_types = sorted(set(row.secret_types or []) | set(ev.secret_types))
            row.injection_detected = ev.injection_detected or row.injection_detected

            # Estimates the Gateway did not supply are filled from config.
            # They are labelled as estimates wherever they are reported; the
            # basis strings live in config/pricing.yaml and
            # config/sustainability.yaml.
            _fill_estimates(row)

            row.gateway_finalized = True
        _bump("events_upserted")
        return True, duplicate
    except Exception as exc:  # noqa: BLE001
        _bump("failures")
        log.error("audit: failed to upsert event %s: %s", ev.request_id, type(exc).__name__)
        return False, False


def record_egress(request_id: str, res: "EgressResponse") -> bool:
    """Persist the egress outcome on the request's row. Never raises."""
    try:
        with session_scope() as s:
            row = s.execute(
                select(RequestAudit).where(RequestAudit.request_id == request_id)
            ).scalar_one_or_none()
            if row is None:
                row = RequestAudit(request_id=request_id)
                s.add(row)
            flagged = res.safety.flagged or res.bias.flagged or res.action.value == "REPLACE"
            row.egress_flagged = flagged or row.egress_flagged
            cats = list(res.safety.categories) + [f"bias:{b}" for b in res.bias.signals]
            if res.action.value != "PASS":
                cats.append(f"action:{res.action.value.lower()}")
            if cats:
                row.egress_categories = sorted(set(row.egress_categories or []) | set(cats))
            if res.grounding.enabled:
                row.grounding_enabled = True
                row.grounding_score = res.grounding.score
                row.grounding_status = res.grounding.status.value
        return True
    except Exception as exc:  # noqa: BLE001
        _bump("failures")
        log.error("audit: failed to record egress %s: %s", request_id, type(exc).__name__)
        return False


def _fill_estimates(row: RequestAudit) -> None:
    """Compute cost / energy / CO2 for a row that has tokens but no figures.

    A cache hit ran no provider inference: its own energy is zero, and its
    savings are what the request would have cost on the counterfactual model.
    """
    from app.audit.estimates import get_pricing, get_sustainability  # noqa: WPS433

    pricing = get_pricing()
    sus = get_sustainability()
    has_tokens = (row.total_tokens or 0) > 0 or (row.input_tokens or 0) > 0

    if row.cache_hit:
        if row.estimated_cost_usd is None:
            row.estimated_cost_usd = 0.0
        if row.estimated_savings_usd is None and has_tokens:
            row.estimated_savings_usd = pricing.cost_usd(
                pricing.savings_counterfactual_model, row.input_tokens, row.output_tokens
            )
        if row.estimated_energy_wh is None:
            row.estimated_energy_wh = 0.0
            row.estimated_co2_g = 0.0
        return

    if not has_tokens:
        return
    if row.estimated_cost_usd is None:
        if row.input_tokens is None and row.output_tokens is None and row.total_tokens:
            # Gateway reported only a total (its contract has `tokens_consumed`).
            # Price it at the model's blended in/out rate rather than reporting
            # a false zero; the pricing basis string already says these are
            # list-price estimates.
            i, o = pricing.rates(row.model)
            row.estimated_cost_usd = round(row.total_tokens * (i + o) / 2 / 1_000_000, 6)
        else:
            row.estimated_cost_usd = pricing.cost_usd(row.model, row.input_tokens, row.output_tokens)
    if row.estimated_energy_wh is None:
        row.estimated_energy_wh = sus.energy_wh(row.model, row.total_tokens or ((row.input_tokens or 0) + (row.output_tokens or 0)))
    if row.estimated_co2_g is None and row.estimated_energy_wh is not None:
        row.estimated_co2_g = sus.co2_g(row.estimated_energy_wh)


def _profile_from_pipeline(res: InspectResponse) -> str | None:
    for st in res.pipeline:
        if st.stage == "policy_engine" and st.detail and "profile=" in st.detail:
            return st.detail.split("profile=", 1)[1].split()[0]
    return None


def _rules_from_pipeline(res: InspectResponse) -> list[str]:
    for st in res.pipeline:
        if st.stage == "policy_engine" and st.detail and "rules=" in st.detail:
            return st.detail.split("rules=", 1)[1].split()[0].split(",")
    return []


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def to_record(row: RequestAudit) -> AuditEventRecord:
    return AuditEventRecord(
        id=row.id,
        request_id=row.request_id,
        tenant_id=row.tenant_id,
        timestamp=row.timestamp,
        provider=row.provider,
        model=row.model,
        policy_action=row.policy_action,
        rules_fired=list(row.rules_fired or []),
        pii_count=row.pii_count,
        secret_count=row.secret_count,
        injection_detected=row.injection_detected,
        cache_hit=row.cache_hit,
        failover_used=row.failover_used,
        grounding_score=row.grounding_score,
        latency_total_ms=row.latency_total_ms,
        total_tokens=row.total_tokens,
        estimated_cost_usd=row.estimated_cost_usd,
        review_id=row.review_id,
    )


def list_events(
    *,
    tenant_id: str = "default",
    limit: int = 50,
    offset: int = 0,
    policy_action: str | None = None,
    since_hours: int = 24,
) -> tuple[list[AuditEventRecord], int]:
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    with session_scope() as s:
        q = select(RequestAudit).where(
            RequestAudit.tenant_id == tenant_id, RequestAudit.timestamp >= since
        )
        if policy_action:
            q = q.where(RequestAudit.policy_action == policy_action.upper())
        total = s.execute(select(func.count()).select_from(q.subquery())).scalar_one()
        rows = s.execute(
            q.order_by(RequestAudit.timestamp.desc()).limit(limit).offset(offset)
        ).scalars().all()
        return [to_record(r) for r in rows], int(total)


def get_event(request_id: str) -> AuditEventRecord | None:
    with session_scope() as s:
        row = s.execute(
            select(RequestAudit).where(RequestAudit.request_id == request_id)
        ).scalar_one_or_none()
        return to_record(row) if row else None


# ---------------------------------------------------------------------------
# Retention and erasure
# ---------------------------------------------------------------------------


def purge_expired(retention_days: int | None = None) -> int:
    """Delete audit rows older than the retention window. Returns count."""
    days = retention_days if retention_days is not None else settings.audit_retention_days
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    with session_scope() as s:
        result = s.execute(delete(RequestAudit).where(RequestAudit.timestamp < cutoff))
        n = int(result.rowcount or 0)
    if n:
        log.info("audit: purged %d row(s) older than %d day(s)", n, days)
    return n


def delete_subject(user_ref: str) -> int:
    """Per-subject erasure: remove every row for one (hashed) user reference."""
    h = hash_user_ref(user_ref)
    if not h:
        return 0
    with session_scope() as s:
        result = s.execute(delete(RequestAudit).where(RequestAudit.user_ref_hash == h))
        n = int(result.rowcount or 0)
    log.info("audit: erased %d row(s) for one subject", n)
    return n


def count_rows() -> int:
    with session_scope() as s:
        return int(s.execute(select(func.count()).select_from(RequestAudit)).scalar_one())
