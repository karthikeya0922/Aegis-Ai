"""Audit write path and audit read APIs.

Real as of Phase 8. The Inspector records its half of each row at /inspect
time; the Gateway posts the other half here once the response completes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.audit import service
from app.contracts.audit import (
    AuditEventPage,
    AuditEventRecord,
    AuditEventRequest,
    AuditEventResponse,
    AuditReport,
)
from app.contracts.common import StrictModel
from app.audit import metrics
from app.utils.logging import get_logger

router = APIRouter(tags=["audit"])
log = get_logger(__name__)


@router.post(
    "/audit/events",
    response_model=AuditEventResponse,
    summary="Record one finalized request",
    description=(
        "Called by the Gateway after a response completes, including after a "
        "stream ends. Idempotent on `request_id`: the first call merges the "
        "Gateway's fields into the row the Inspector already wrote; a repeat "
        "is accepted and flagged `duplicate`.\n\n"
        "A failed audit write must never fail the user's request -- the "
        "Gateway should fire-and-forget and count its own failures.\n\n"
        "`user_ref` is hashed on arrival and the raw value is discarded. The "
        "model has no field for prompt text, keys or passwords, and the "
        "schema has no column for them, so they cannot be persisted."
    ),
)
async def write_audit_event(req: AuditEventRequest) -> AuditEventResponse:
    stored, duplicate = service.upsert_event(req)
    log.info(
        "audit request_id=%s stored=%s duplicate=%s provider=%s",
        req.request_id, stored, duplicate, req.provider or "-",
        extra={"request_id": req.request_id},
    )
    return AuditEventResponse(stored=stored, request_id=req.request_id, duplicate=duplicate)


@router.get(
    "/api/audit/events",
    response_model=AuditEventPage,
    summary="Paginated decision log",
)
async def list_audit_events(
    tenant_id: str = Query("default"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    policy_action: str | None = Query(None, description="ALLOW | WARN | SANITIZE | BLOCK"),
    since_hours: int = Query(24, ge=1, le=8760),
) -> AuditEventPage:
    items, total = service.list_events(
        tenant_id=tenant_id, limit=limit, offset=offset,
        policy_action=policy_action, since_hours=since_hours,
    )
    return AuditEventPage(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/api/requests/{request_id}",
    response_model=AuditEventRecord,
    summary="One request's audit record",
)
async def get_request(request_id: str) -> AuditEventRecord:
    rec = service.get_event(request_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="No audit record for that request_id")
    return rec


@router.get(
    "/api/audit/report",
    response_model=AuditReport,
    summary="Structured audit export",
    description=(
        "Structured sections the Gateway renders, one per Trustworthy AI "
        "requirement, each a set of evidence rows from the audit table with a "
        "note saying what the numbers are and are not. Carries a disclaimer: "
        "this is transaction evidence supporting a deployer's own obligations, "
        "not a conformity assessment."
    ),
)
async def audit_report(
    tenant_id: str = Query("default"),
    since_hours: int = Query(168, ge=1, le=8760),
) -> AuditReport:
    return metrics.report(tenant_id, since_hours)


# ---------------------------------------------------------------------------
# Retention and erasure -- the audit log is a surveillance capability and is
# constrained accordingly (spec s5.5)
# ---------------------------------------------------------------------------


class PurgeResponse(StrictModel):
    deleted: int
    retention_days: int


class EraseSubjectRequest(StrictModel):
    user_ref: str


class EraseSubjectResponse(StrictModel):
    deleted: int


@router.post(
    "/api/audit/purge",
    response_model=PurgeResponse,
    summary="Delete rows older than the retention window",
    description=(
        "Runs the retention policy now. Phase 16 schedules this; until then "
        "an operator triggers it. Rows older than AEGIS_AUDIT_RETENTION_DAYS "
        "(or the `retention_days` override) are deleted."
    ),
)
async def purge(retention_days: int | None = Query(None, ge=0, le=3650)) -> PurgeResponse:
    from app.config import settings

    days = retention_days if retention_days is not None else settings.audit_retention_days
    return PurgeResponse(deleted=service.purge_expired(days), retention_days=days)


@router.post(
    "/api/audit/erase-subject",
    response_model=EraseSubjectResponse,
    status_code=status.HTTP_200_OK,
    summary="Erase every audit row for one user (right to erasure)",
    description=(
        "The raw `user_ref` is hashed with the deployment salt and every row "
        "with that hash is deleted. The raw value is not logged or stored by "
        "this call either. Returns the number of rows removed."
    ),
)
async def erase_subject(req: EraseSubjectRequest) -> EraseSubjectResponse:
    n = service.delete_subject(req.user_ref)
    log.info("audit: subject erasure removed %d row(s)", n)
    return EraseSubjectResponse(deleted=n)
