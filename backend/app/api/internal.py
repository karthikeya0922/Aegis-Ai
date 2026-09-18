"""`/internal/*` -- the Gateway's contract, served by the real Inspector.

Person 2 built the Next.js gateway against `lib/types/aegis.ts` and the mock
in `mocks/engine/server.ts`: `/internal/scan`, `/internal/verify`,
`/internal/audit*`, `/internal/policies`, `/internal/health`. The Inspector's
native contract (`/inspect`, `/inspect/egress`, `/verify`, `/audit/events`,
`/api/*`) is richer and stays the source of truth. This module is a thin
translation layer so the two halves run together without either being
rewritten. Every verdict here comes from the same pipeline, policy engine and
audit table as the native endpoints -- nothing is re-implemented.

Two honest compromises:

  * The Gateway expects an opaque `vault_token` it can hand back on egress
    for rehydration. The Inspector is stateless by design, so this layer
    keeps a small in-process TTL map (token -> placeholder map). It is
    per-replica and expires after `AEGIS_VAULT_TTL_SECONDS`; secrets are
    never stored in it, so they can never be rehydrated.
  * `Detection.match` is required by the Gateway's schema. For PII it is the
    original value (the Gateway's own `inspector.ts` redacts before display);
    for secrets and injection it is never the raw value.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.audit import metrics
from app.audit import service as audit
from app.audit.database import session_scope
from app.audit.models import RequestAudit
from app.audit.service import record_egress, record_inspection
from app.config import settings
from app.contracts.audit import AuditEventRequest
from app.contracts.common import Decision, DetectionCategory, GroundingStatus, Message
from app.contracts.egress import EgressRequest
from app.contracts.inspect import InspectRequest, InspectResponse
from app.security.pipeline import get_pipeline
from app.security.policy_engine import get_policy_engine
from app.utils.logging import get_logger
from app.verification.egress import run_egress

router = APIRouter(prefix="/internal", tags=["gateway-compat"])
log = get_logger(__name__)


class Loose(BaseModel):
    """The Gateway's types are TypeScript; tolerate extra keys rather than 422."""

    model_config = ConfigDict(extra="ignore")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Vault handles
# ---------------------------------------------------------------------------


class _VaultStore:
    def __init__(self) -> None:
        self._items: dict[str, tuple[float, dict[str, str]]] = {}
        self._lock = threading.Lock()

    def put(self, mapping: dict[str, str]) -> str:
        token = f"vault_{uuid.uuid4().hex}"
        with self._lock:
            self._sweep()
            self._items[token] = (time.monotonic() + settings.vault_ttl_seconds, dict(mapping))
        return token

    def get(self, token: str) -> dict[str, str] | None:
        with self._lock:
            self._sweep()
            hit = self._items.get(token)
            return dict(hit[1]) if hit else None

    def _sweep(self) -> None:
        now = time.monotonic()
        for k in [k for k, (exp, _) in self._items.items() if exp <= now]:
            del self._items[k]

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


VAULT = _VaultStore()


# ---------------------------------------------------------------------------
# Mapping tables
# ---------------------------------------------------------------------------

_PII_CATEGORY = {
    "EMAIL_ADDRESS": "PII_EMAIL", "PHONE_NUMBER": "PII_PHONE", "US_SSN": "PII_SSN",
    "CREDIT_CARD": "PII_CREDIT_CARD", "PERSON": "PII_PERSON_NAME",
}
_SECRET_CATEGORY = {
    "AWS_ACCESS_KEY": "SECRET_AWS_ACCESS_KEY", "AWS_SECRET_KEY": "SECRET_AWS_SECRET_KEY",
    "DATABASE_CREDENTIAL": "SECRET_DB_CONNECTION_STRING", "URI_CREDENTIAL": "SECRET_DB_CONNECTION_STRING",
    "JWT": "SECRET_JWT",
}
_ACTION = {Decision.ALLOW: "allow", Decision.SANITIZE: "sanitize", Decision.WARN: "warn", Decision.BLOCK: "block"}
_STAGE_STATUS = {
    "success": "pass", "hit": "pass", "miss": "pass",
    "warning": "flagged", "blocked": "blocked", "skipped": "skipped", "error": "skipped",
}
_GROUNDING = {
    GroundingStatus.GROUNDED: "pass", GroundingStatus.REVIEW: "warn",
    GroundingStatus.UNGROUNDED: "block", GroundingStatus.SKIPPED: "pass",
}
_GROUNDING_IN = {"pass": "GROUNDED", "warn": "REVIEW", "block": "UNGROUNDED"}


def _category(det_type: str, cat: DetectionCategory) -> str:
    if cat is DetectionCategory.SECRET:
        return _SECRET_CATEGORY.get(det_type, "SECRET_API_KEY")
    return _PII_CATEGORY.get(det_type, f"PII_{det_type}")


def _error_code(res: InspectResponse) -> str | None:
    if res.decision is not Decision.BLOCK:
        return None
    code = (res.block_reason.code if res.block_reason else "") or ""
    if code in {"CREDENTIAL_LEAK_PREVENTED", "PROMPT_INJECTION_BLOCKED"}:
        return code
    if code.startswith("PII"):
        return "PII_LEAK_PREVENTED"
    if res.detections.secrets:
        return "CREDENTIAL_LEAK_PREVENTED"
    if res.detections.injection.detected:
        return "PROMPT_INJECTION_BLOCKED"
    if res.detections.pii:
        return "PII_LEAK_PREVENTED"
    return "POLICY_VIOLATION"


def _stages(pipeline) -> list[dict[str, Any]]:
    out = []
    for st in pipeline:
        d: dict[str, Any] = {"name": st.stage, "status": _STAGE_STATUS.get(st.status.value, "skipped"),
                             "duration_ms": st.duration_ms}
        if st.detail:
            d["detail"] = st.detail
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# POST /internal/scan
# ---------------------------------------------------------------------------


class ScanIn(Loose):
    request_id: str | None = None
    session_id: str | None = None
    messages: list[Message]
    mode: Literal["sanitize", "strict"] | None = "sanitize"
    confidential_mode: bool = False
    metadata: dict[str, str] | None = None


@router.post("/scan", summary="Gateway contract: ingress scan")
async def scan(body: ScanIn) -> dict[str, Any]:
    rid = body.request_id or f"req_{uuid.uuid4().hex[:12]}"
    strict = body.mode == "strict" or body.confidential_mode
    tenant = (body.metadata or {}).get("tenant_id", "default")
    req = InspectRequest(
        request_id=rid, tenant_id=tenant, user_ref=body.session_id, messages=body.messages,
        mode="strict" if strict else None, policy_profile="strict" if strict else None,
    )
    res = get_pipeline().run(req)
    record_inspection(req, res)

    detections: list[dict[str, Any]] = []
    for d in res.detections.pii:
        original = res.vault.get(d.placeholder, "") if d.placeholder else ""
        detections.append({
            "category": _category(d.type, d.category), "match": original or (d.placeholder or ""),
            "placeholder": d.placeholder, "start": d.start, "end": d.end,
            "confidence": d.confidence, "message_index": d.message_index,
        })
    for d in res.detections.secrets:
        detections.append({
            "category": _category(d.type, d.category), "match": "[REDACTED]",
            "placeholder": d.placeholder, "start": d.start, "end": d.end,
            "confidence": d.confidence, "message_index": d.message_index,
        })
    inj = res.detections.injection
    if inj.detected:
        for rule in inj.matched_rules or ["injection"]:
            detections.append({
                "category": "PROMPT_INJECTION", "match": rule, "placeholder": None,
                "start": 0, "end": 0, "confidence": inj.score, "message_index": 0,
            })

    action = _ACTION[res.decision]
    sanitized = None
    vault_token = None
    if action == "sanitize":
        sanitized = [{"role": m.role, "content": m.content} for m in res.messages]
        # Only PII placeholders go into the handle. Secrets are never rehydrated.
        pii_placeholders = {d.placeholder for d in res.detections.pii if d.placeholder}
        rehydratable = {k: v for k, v in res.vault.items() if k in pii_placeholders}
        vault_token = VAULT.put(rehydratable) if rehydratable else None

    return {
        "request_id": rid, "action": action, "error_code": _error_code(res),
        "detections": detections, "sanitized_messages": sanitized, "vault_token": vault_token,
        "stages": _stages(res.pipeline), "processed_at": _now_iso(),
        # extras the native contract carries; harmless to the Gateway's schema
        "explanation": res.explanation, "policy_version": res.policy_version,
        "cache": res.cache.model_dump(mode="json"), "routing_hint": res.routing_hint.model_dump(mode="json"),
    }


# ---------------------------------------------------------------------------
# POST /internal/verify
# ---------------------------------------------------------------------------


class VerifyIn(Loose):
    request_id: str | None = None
    vault_token: str | None = None
    response_text: str
    reference_documents: list[str] = Field(default_factory=list)
    rehydrate: bool = False


@router.post("/verify", summary="Gateway contract: egress screens, grounding, rehydration")
async def verify(body: VerifyIn) -> dict[str, Any]:
    rid = body.request_id or f"req_{uuid.uuid4().hex[:12]}"
    reference = "\n\n".join(d for d in body.reference_documents if d.strip()) or None
    checks = ["harm", "bias"] + (["grounding"] if reference else [])
    egress = run_egress(EgressRequest(request_id=rid, response_text=body.response_text,
                                      reference_context=reference, checks=checks))
    record_egress(rid, egress)

    stages = _stages(egress.pipeline)
    # The screens' REPLACE is ours to apply (the Gateway has no fallback for harm).
    # A grounding REPLACE is reported as status "block" and the Gateway substitutes
    # its own configured fallback -- that is its contract, so final_text keeps the
    # original there and we do not double-replace.
    replaced_by_screens = (
        egress.action.value == "REPLACE" and egress.replacement_text
        and (egress.safety.flagged or egress.bias.flagged)
    )
    final_text = egress.replacement_text if replaced_by_screens else body.response_text

    rehydrated = False
    t0 = time.perf_counter()
    if body.rehydrate and body.vault_token and settings.pii_rehydration and not replaced_by_screens:
        mapping = VAULT.get(body.vault_token)
        if mapping:
            for placeholder, original in mapping.items():
                if placeholder in final_text:
                    final_text = final_text.replace(placeholder, original)
                    rehydrated = True
            stages.append({"name": "rehydration", "status": "flagged" if rehydrated else "skipped",
                           "duration_ms": round((time.perf_counter() - t0) * 1000, 3),
                           "detail": f"{len(mapping)} placeholder(s) available"})
        else:
            stages.append({"name": "rehydration", "status": "skipped", "duration_ms": 0.0,
                           "detail": "vault_token unknown or expired"})
    else:
        stages.append({"name": "rehydration", "status": "skipped", "duration_ms": 0.0,
                       "detail": "not requested" if not body.rehydrate else "no vault_token"})

    g = egress.grounding
    g_status = _GROUNDING[g.status]
    # A harm/bias REPLACE is not a grounding failure, but the Gateway has only one
    # 'block' lever. We already substituted the fallback into final_text, so tell
    # it 'pass' and let final_text carry the replacement.
    return {
        "request_id": rid, "final_text": final_text, "rehydrated": rehydrated,
        "grounding": {"status": g_status, "score": g.score if g.score is not None else 1.0,
                      "unsupported_claims": list(g.unsupported_claims)},
        "stages": stages, "processed_at": _now_iso(),
        "egress_action": egress.action.value, "explanation": egress.explanation,
        "safety": egress.safety.model_dump(mode="json"), "bias": egress.bias.model_dump(mode="json"),
    }


# ---------------------------------------------------------------------------
# Audit: POST /internal/audit, GET /internal/audit, GET /internal/audit/events
# ---------------------------------------------------------------------------


class AuditEntryIn(Loose):
    request_id: str
    model_used: str | None = None
    tokens_consumed: int | None = None
    latency_ms: float | None = None
    scrubbed_entity_count: int = 0
    rule_triggers: list[str] = Field(default_factory=list)
    action: str = "allow"
    error_code: str | None = None
    provider_used: str | None = None
    cache_hit: bool = False
    failover_used: bool = False
    grounding_status: str | None = None
    grounding_score: float | None = None
    estimated_cost_usd: float | None = None
    estimated_savings_usd: float | None = None
    estimated_carbon_g: float | None = None


class AuditIn(Loose):
    entry: AuditEntryIn


@router.post("/audit", status_code=status.HTTP_201_CREATED, summary="Gateway contract: finalize an audit row")
async def write_audit(body: AuditIn) -> dict[str, Any]:
    e = body.entry
    ev = AuditEventRequest(
        request_id=e.request_id, provider=e.provider_used, model=e.model_used,
        latency_total_ms=e.latency_ms, total_tokens=e.tokens_consumed,
        cache_hit=e.cache_hit, failover_used=e.failover_used,
        grounding_enabled=e.grounding_status in _GROUNDING_IN,
        grounding_status=GroundingStatus(_GROUNDING_IN[e.grounding_status]) if e.grounding_status in _GROUNDING_IN else None,
        grounding_score=e.grounding_score,
        estimated_cost_usd=e.estimated_cost_usd, estimated_savings_usd=e.estimated_savings_usd,
        estimated_co2_g=e.estimated_carbon_g,
        policy_action=Decision(e.action.upper()) if e.action.upper() in Decision.__members__ else None,
    )
    audit.upsert_event(ev)
    row = _row(e.request_id)
    entry = _entry(row) if row else {"id": str(uuid.uuid4()), "timestamp": _now_iso(), **e.model_dump()}
    return {"entry": entry}


def _row(request_id: str) -> RequestAudit | None:
    with session_scope() as s:
        row = s.execute(select(RequestAudit).where(RequestAudit.request_id == request_id)).scalar_one_or_none()
        if row:
            s.expunge(row)
        return row


def _rule_triggers(row: RequestAudit) -> list[str]:
    out = [_PII_CATEGORY.get(t, f"PII_{t}") for t in (row.pii_types or [])]
    out += [_SECRET_CATEGORY.get(t, "SECRET_API_KEY") for t in (row.secret_types or [])]
    if row.injection_detected:
        out.append("PROMPT_INJECTION")
    return out


def _entry(row: RequestAudit) -> dict[str, Any]:
    action = (row.policy_action or "ALLOW").lower()
    code = row.block_code
    if action == "block" and code and code.startswith("PII"):
        code = "PII_LEAK_PREVENTED"
    ts = row.timestamp if row.timestamp.tzinfo else row.timestamp.replace(tzinfo=timezone.utc)
    gs = row.grounding_status
    return {
        "id": str(row.id), "request_id": row.request_id,
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "model_used": row.model, "tokens_consumed": row.total_tokens, "latency_ms": row.latency_total_ms,
        "scrubbed_entity_count": int(row.pii_count or 0) + int(row.secret_count or 0),
        "rule_triggers": _rule_triggers(row),
        "action": action, "error_code": code if action == "block" else None,
        "provider_used": row.provider, "cache_hit": bool(row.cache_hit), "failover_used": bool(row.failover_used),
        "grounding_status": _GROUNDING[GroundingStatus(gs)] if gs in GroundingStatus.__members__ and gs != "SKIPPED" else None,
        "grounding_score": row.grounding_score,
        "estimated_cost_usd": row.estimated_cost_usd, "estimated_savings_usd": row.estimated_savings_usd,
        "estimated_carbon_g": row.estimated_co2_g,
        "tenant_id": row.tenant_id, "policy_version": row.policy_version, "rules_fired": list(row.rules_fired or []),
    }


def _parse_ts(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"bad timestamp: {v!r}")
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _query_rows(*, from_: str | None, to: str | None, provider: str | None, action: str | None,
                cache_hit: str | None, has_detections: str | None, tenant_id: str) -> list[RequestAudit]:
    since = _parse_ts(from_) or (datetime.now(timezone.utc) - timedelta(days=365))
    until = _parse_ts(to)
    with session_scope() as s:
        q = select(RequestAudit).where(RequestAudit.tenant_id == tenant_id, RequestAudit.timestamp >= since)
        if until:
            q = q.where(RequestAudit.timestamp < until)
        if provider:
            q = q.where(RequestAudit.provider == provider)
        if action:
            q = q.where(RequestAudit.policy_action == action.upper())
        if cache_hit in ("true", "false"):
            q = q.where(RequestAudit.cache_hit.is_(cache_hit == "true"))
        rows = s.execute(q.order_by(RequestAudit.timestamp.desc())).scalars().all()
        for r in rows:
            s.expunge(r)
    if has_detections in ("true", "false"):
        want = has_detections == "true"
        rows = [r for r in rows if bool(_rule_triggers(r)) == want]
    return list(rows)


@router.get("/audit/events", summary="Gateway contract: filtered, paginated audit trail")
async def audit_events(
    from_: str | None = Query(None, alias="from"), to: str | None = None,
    provider: str | None = None, action: str | None = None,
    cache_hit: str | None = None, has_detections: str | None = None,
    limit: int = Query(25, ge=1, le=5000), offset: int = Query(0, ge=0),
    tenant_id: str = "default",
) -> dict[str, Any]:
    rows = _query_rows(from_=from_, to=to, provider=provider, action=action, cache_hit=cache_hit,
                       has_detections=has_detections, tenant_id=tenant_id)
    return {"entries": [_entry(r) for r in rows[offset:offset + limit]], "total": len(rows)}


@router.get("/audit", summary="Gateway contract: recent audit entries")
async def audit_query(
    from_: str | None = Query(None, alias="from"), to: str | None = None,
    limit: int | None = Query(None, ge=1, le=5000), tenant_id: str = "default",
) -> dict[str, Any]:
    rows = _query_rows(from_=from_, to=to, provider=None, action=None, cache_hit=None,
                       has_detections=None, tenant_id=tenant_id)
    entries = [_entry(r) for r in rows]
    entries.reverse()  # oldest first, like the mock; `limit` keeps the newest
    if limit:
        entries = entries[-limit:]
    return {"entries": entries, "total": len(rows)}


# ---------------------------------------------------------------------------
# GET /internal/audit/report -- a real PDF from the structured report
# ---------------------------------------------------------------------------


def _pdf(lines: list[str]) -> bytes:
    """Minimal single-font, multi-page PDF. No library: the dashboard only
    needs a valid download, and the structured report is at /api/audit/report."""
    def esc(t: str) -> str:
        return t.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    per_page = 46
    pages = [lines[i:i + per_page] for i in range(0, max(len(lines), 1), per_page)] or [[]]
    objects: list[str] = []
    # 1 catalog, 2 pages, 3 font, then per page: page obj + content obj
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{4 + 2 * i} 0 R" for i in range(len(pages)))
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>")
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for i, page in enumerate(pages):
        content = "\n".join(
            f"BT /F1 {11 if j else 14} Tf 50 {760 - j * 15} Td ({esc(l)}) Tj ET" for j, l in enumerate(page)
        )
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                       f"/Resources << /Font << /F1 3 0 R >> >> /Contents {5 + 2 * i} 0 R >>")
        objects.append(f"<< /Length {len(content.encode('latin-1', 'replace'))} >>\nstream\n{content}\nendstream")
    out = "%PDF-1.4\n"
    offsets = []
    for i, o in enumerate(objects):
        offsets.append(len(out.encode("latin-1", "replace")))
        out += f"{i + 1} 0 obj\n{o}\nendobj\n"
    xref = len(out.encode("latin-1", "replace"))
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
    out += "".join(f"{off:010d} 00000 n \n" for off in offsets)
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
    return out.encode("latin-1", "replace")


@router.get("/audit/report", summary="Gateway contract: audit report as PDF")
async def audit_report_pdf(
    from_: str | None = Query(None, alias="from"), to: str | None = None, tenant_id: str = "default",
) -> Response:
    since = _parse_ts(from_)
    hours = 168
    if since:
        hours = max(1, min(8760, int((datetime.now(timezone.utc) - since).total_seconds() // 3600) + 1))
    rep = metrics.report(tenant_id, hours)
    rows = _query_rows(from_=from_, to=to, provider=None, action=None, cache_hit=None,
                       has_detections=None, tenant_id=tenant_id)
    blocked = sum(1 for r in rows if (r.policy_action or "") == "BLOCK")
    scrubbed = sum(int(r.pii_count or 0) + int(r.secret_count or 0) for r in rows)

    lines = [
        "Aegis Audit Report",
        f"Window: {from_ or f'last {hours}h'} to {to or 'now'}    Tenant: {tenant_id}",
        f"Generated: {_now_iso()}",
        f"Requests: {len(rows)}    Blocked: {blocked}    Entities scrubbed: {scrubbed}",
        "",
    ]
    for section in rep.sections:
        lines.append(section.title + (f"  [{section.requirement}]" if section.requirement else ""))
        for row in section.rows:
            basis = row.get("basis")
            lines.append(f"   {row.get('metric')}: {row.get('value')}" + (f"   ({basis})" if basis else ""))
        if section.note:
            lines.append(f"   note: {section.note}")
        lines.append("")
    disclaimer = rep.disclaimer
    if disclaimer:
        lines.append("Disclaimer:")
        # wrap at ~95 chars
        words, cur = disclaimer.split(), ""
        for w in words:
            if len(cur) + len(w) + 1 > 95:
                lines.append("   " + cur); cur = w
            else:
                cur = f"{cur} {w}".strip()
        if cur:
            lines.append("   " + cur)
    pdf = _pdf(lines)
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="aegis-audit-report.pdf"'})


# ---------------------------------------------------------------------------
# GET /internal/policies (derived, read-only) and GET /internal/health
# ---------------------------------------------------------------------------


@router.get("/policies", summary="Gateway contract: the active profile as feature flags")
async def policies() -> dict[str, Any]:
    eng = get_policy_engine()
    prof = eng.policies.profiles.get(settings.policy_profile) or eng.policies.profiles[eng.policies.default_profile]
    rules = prof.rules

    def enabled(prefix: str) -> bool:
        return any(k.startswith(prefix) and r.action.value != "allow" for k, r in rules.items())

    grounding = rules.get("grounding")
    replace_below = getattr(grounding, "params", {}).get("replace_below") if grounding else None
    return {
        "policy": {
            "pii_detection_enabled": enabled("pii"),
            "secret_detection_enabled": enabled("secrets"),
            "prompt_injection_detection_enabled": enabled("prompt_injection"),
            "hallucination_check_enabled": grounding is not None,
            "faithfulness_threshold": float(replace_below if replace_below is not None else settings.grounding_replace_below),
            "block_on_pii": any(k.startswith("pii") and r.action.value == "block" for k, r in rules.items()),
        },
        "updated_at": _now_iso(),
        "profile": settings.policy_profile, "policy_version": eng.policies.version,
        "note": "Derived view. Edit policy through PUT /api/policies (versioned, admin-gated).",
    }


@router.put("/policies", summary="Gateway contract: not supported here", status_code=status.HTTP_405_METHOD_NOT_ALLOWED)
async def policies_put() -> dict[str, Any]:
    return {"error": "Policy is versioned YAML. Use PUT /api/policies with X-Admin-Token."}


_STARTED = time.monotonic()


@router.get("/health", summary="Gateway contract: liveness")
async def health() -> dict[str, Any]:
    from app.api.health import _components

    comps = _components()
    not_ok = [c for c in comps if c.status != "ok"]
    return {
        "status": "degraded" if not_ok else "ok", "engine": "python",
        "version": settings.version, "uptime_s": round(time.monotonic() - _STARTED),
        "degraded": [c.name for c in not_ok],
    }
