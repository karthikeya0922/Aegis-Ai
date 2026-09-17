"""Audit write path and audit read APIs."""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.contracts.audit import (
    AuditEventPage,
    AuditEventRequest,
    AuditEventResponse,
    AuditReport,
)
from app.stubs import stub_audit_page, stub_audit_report
from app.utils.ids import hash_user_ref
from app.utils.logging import get_logger

router = APIRouter(tags=["audit"])
log = get_logger(__name__)


@router.post(
    "/audit/events",
    response_model=AuditEventResponse,
    summary="Record one finalized request",
    description=(
        "Called by the Gateway after a response completes, including after a "
        "stream ends. Idempotent on `request_id`.\n\n"
        "A failed audit write must never fail the user's request -- the "
        "Gateway should fire-and-forget and increment its own "
        "`audit_write_failures` counter.\n\n"
        "`user_ref` is hashed on arrival and the raw value is discarded. The "
        "model has no field for prompt text, keys or passwords, so they cannot "
        "be persisted even by accident."
    ),
)
async def write_audit_event(req: AuditEventRequest) -> AuditEventResponse:
    _ = hash_user_ref(req.user_ref)  # Phase 8 persists this; raw value never stored
    log.info(
        "audit request_id=%s action=%s provider=%s cache_hit=%s",
        req.request_id,
        req.policy_action.value if req.policy_action else "-",
        req.provider or "-",
        req.cache_hit,
        extra={"request_id": req.request_id},
    )
    return AuditEventResponse(stored=True, request_id=req.request_id, duplicate=False)


@router.get(
    "/api/audit/events",
    response_model=AuditEventPage,
    summary="Paginated decision log",
)
async def list_audit_events(
    tenant_id: str = Query("default"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    policy_action: str | None = Query(None),
    since_hours: int = Query(24, ge=1, le=8760),
) -> AuditEventPage:
    return stub_audit_page(limit=limit, offset=offset)


@router.get(
    "/api/audit/report",
    response_model=AuditReport,
    summary="Structured audit export",
    description=(
        "Returns structured sections the Gateway renders. Carries a disclaimer "
        "stating that this is transaction evidence supporting a deployer's own "
        "obligations, not a conformity assessment."
    ),
)
async def audit_report(
    tenant_id: str = Query("default"),
    since_hours: int = Query(168, ge=1, le=8760),
) -> AuditReport:
    return stub_audit_report(tenant_id)
