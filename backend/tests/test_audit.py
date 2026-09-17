"""Phase 8 -- the database layer.

The load-bearing tests are the privacy ones: no raw prompt, credential or
user identifier can reach a row, by schema and by allowlist. The rest pin
the two-phase write, idempotency, retention and erasure.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, update

from app.audit import database, service
from app.audit.database import Base, session_scope
from app.audit.models import (
    FORBIDDEN_COLUMN_NAMES,
    FairnessEval,
    PolicyVersion,
    RequestAudit,
    ReviewRequest,
)
from app.contracts.audit import AuditEventRequest
from app.contracts.common import Decision, GroundingStatus, Message
from app.contracts.inspect import InspectRequest
from app.security.pipeline import get_pipeline
from app.utils.ids import hash_user_ref


@pytest.fixture(autouse=True)
def _clean_tables():
    with session_scope() as s:
        for table in (RequestAudit, ReviewRequest, PolicyVersion, FairnessEval):
            s.query(table).delete()
    yield


def inspect(request_id: str, text: str, user_ref: str | None = None):
    req = InspectRequest(request_id=request_id, user_ref=user_ref,
                         messages=[Message(role="user", content=text)])
    return req, get_pipeline().run(req)


def raw_row(request_id: str) -> RequestAudit:
    with session_scope() as s:
        return s.execute(select(RequestAudit).where(RequestAudit.request_id == request_id)).scalar_one()


def row_dump(row: RequestAudit) -> str:
    return " ".join(f"{k}={v!r}" for k, v in vars(row).items() if not k.startswith("_"))


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_tables_exist():
    assert {"request_audit", "review_request", "policy_version", "fairness_eval"} <= set(Base.metadata.tables)
    assert database.ping()


def test_no_table_has_a_forbidden_column():
    """The schema itself cannot hold a prompt, a credential or a raw identity."""
    offenders = [
        (t, c)
        for t, tbl in Base.metadata.tables.items()
        for c in tbl.columns.keys()
        if c in FORBIDDEN_COLUMN_NAMES
    ]
    assert offenders == [], offenders


def test_request_id_is_unique():
    with session_scope() as s:
        s.add(RequestAudit(request_id="req_dup"))
    with pytest.raises(Exception):
        with session_scope() as s:
            s.add(RequestAudit(request_id="req_dup"))


# ---------------------------------------------------------------------------
# Inspector half
# ---------------------------------------------------------------------------


def test_record_inspection_writes_the_decision():
    req, res = inspect("req_a1", "mail john@example.com and key AKIAIOSFODNN7EXAMPLE", user_ref="alice")
    assert service.record_inspection(req, res) is True
    row = raw_row("req_a1")
    assert row.policy_action == "BLOCK"
    assert row.block_code == "CREDENTIAL_LEAK_PREVENTED"
    assert row.pii_detected and row.pii_count == 1 and row.pii_types == ["EMAIL_ADDRESS"]
    assert row.secret_detected and row.secret_count == 1 and row.secret_types == ["AWS_ACCESS_KEY"]
    assert row.injection_detected is False
    assert row.policy_profile == "default"
    assert "secrets" in row.rules_fired
    assert row.routed_complexity == "LOW"
    assert row.latency_inspect_ms == res.total_duration_ms
    assert set(row.stage_timings_ms) >= {"pii_scanner", "policy_engine"}
    assert row.gateway_finalized is False


def test_record_inspection_never_raises(monkeypatch):
    """A broken database must not fail the user's request."""
    req, res = inspect("req_a2", "hello")

    def boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(service, "session_scope", boom)
    before = service.stats().failures
    assert service.record_inspection(req, res) is False
    assert service.stats().failures == before + 1


# ---------------------------------------------------------------------------
# Gateway half and idempotency
# ---------------------------------------------------------------------------


def test_upsert_merges_gateway_fields_into_inspector_row():
    req, res = inspect("req_b1", "mail john@example.com")
    service.record_inspection(req, res)
    stored, dup = service.upsert_event(AuditEventRequest(
        request_id="req_b1", provider="openai", model="gpt-4o-mini",
        input_tokens=40, output_tokens=90, total_tokens=130,
        latency_total_ms=210.0, cache_hit=False, estimated_cost_usd=0.0002,
        grounding_enabled=True, grounding_score=0.8, grounding_status=GroundingStatus.REVIEW,
    ))
    assert stored and not dup
    row = raw_row("req_b1")
    # Inspector fields survive
    assert row.policy_action == "SANITIZE" and row.pii_count == 1
    # Gateway fields landed
    assert row.provider == "openai" and row.total_tokens == 130
    assert row.grounding_status == "REVIEW" and row.grounding_score == 0.8
    assert row.gateway_finalized is True


def test_upsert_is_idempotent_and_flags_duplicates():
    ev = AuditEventRequest(request_id="req_b2", provider="p", total_tokens=10)
    assert service.upsert_event(ev) == (True, False)
    assert service.upsert_event(ev) == (True, True)
    assert service.count_rows() == 1


def test_upsert_without_prior_inspection_creates_the_row():
    """A Gateway that posts before (or without) an inspect call still leaves a record."""
    stored, _ = service.upsert_event(AuditEventRequest(
        request_id="req_b3", tenant_id="acme", policy_action=Decision.ALLOW, cache_hit=True,
    ))
    assert stored
    row = raw_row("req_b3")
    assert row.tenant_id == "acme" and row.cache_hit is True and row.policy_action == "ALLOW"


def test_upsert_does_not_clear_fields_with_none():
    service.upsert_event(AuditEventRequest(request_id="req_b4", provider="openai", total_tokens=5))
    service.upsert_event(AuditEventRequest(request_id="req_b4", provider=None, total_tokens=None, cache_hit=True))
    row = raw_row("req_b4")
    assert row.provider == "openai" and row.total_tokens == 5 and row.cache_hit is True


def test_upsert_unions_list_fields():
    service.upsert_event(AuditEventRequest(request_id="req_b5", rules_fired=["pii"], pii_types=["EMAIL_ADDRESS"], pii_count=1))
    service.upsert_event(AuditEventRequest(request_id="req_b5", rules_fired=["prompt_injection"], pii_types=["PERSON"], pii_count=2))
    row = raw_row("req_b5")
    assert row.rules_fired == ["pii", "prompt_injection"]
    assert row.pii_types == ["EMAIL_ADDRESS", "PERSON"]
    assert row.pii_count == 2


# ---------------------------------------------------------------------------
# Privacy invariants -- the reason this layer exists
# ---------------------------------------------------------------------------


def test_no_raw_value_reaches_the_row():
    req, res = inspect(
        "req_p1",
        "Priya Ramaswamy, john@example.com, AKIAIOSFODNN7EXAMPLE, "
        "postgres://admin:SecretPassword@db.internal/x, Aadhaar 2345 6789 0124",
        user_ref="alice@corp.example",
    )
    service.record_inspection(req, res)
    service.upsert_event(AuditEventRequest(request_id="req_p1", user_ref="alice@corp.example", provider="p"))
    dump = row_dump(raw_row("req_p1"))
    for raw in ("Priya", "Ramaswamy", "john@example.com", "AKIAIOSFODNN7EXAMPLE",
                "SecretPassword", "2345 6789 0124", "alice@corp.example", "alice"):
        assert raw not in dump, f"{raw!r} reached the audit row"


def test_user_ref_is_hashed_and_salted():
    req, res = inspect("req_p2", "hi", user_ref="alice")
    service.record_inspection(req, res)
    row = raw_row("req_p2")
    assert row.user_ref_hash == hash_user_ref("alice")
    assert row.user_ref_hash != "alice"
    assert len(row.user_ref_hash) == 32


def test_the_write_path_has_no_generic_setter():
    """No function takes **kwargs, and no loop iterates the incoming event's
    fields: an unknown field has no route into a row. Checked on the AST so
    a comment or docstring cannot trip it."""
    import ast
    import inspect as _inspect

    tree = ast.parse(_inspect.getsource(service))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assert node.args.kwarg is None, f"{node.name} accepts **kwargs"
        if isinstance(node, ast.For):
            # A loop over the event object itself (vars(ev), ev.__dict__,
            # ev.model_dump()) would be a generic setter; loops over literal
            # tuples of allowed names are fine.
            it = ast.unparse(node.iter)
            assert not any(tok in it for tok in ("vars(ev", "ev.__dict__", "ev.model_dump", "ev.dict(")), it


def test_override_token_hash_helper():
    h = service.token_hash("ovr_abc")
    assert h != "ovr_abc" and len(h) == 64
    assert service.token_hash("ovr_abc") == h


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def test_list_events_pagination_and_filter():
    for i in range(5):
        req, res = inspect(f"req_l{i}", "mail john@example.com" if i % 2 else "hello")
        service.record_inspection(req, res)
    items, total = service.list_events(limit=2, offset=0)
    assert total == 5 and len(items) == 2
    items, total = service.list_events(policy_action="sanitize")
    assert total == 2 and all(r.policy_action == "SANITIZE" for r in items)


def test_list_events_is_tenant_scoped():
    service.upsert_event(AuditEventRequest(request_id="req_t1", tenant_id="a"))
    service.upsert_event(AuditEventRequest(request_id="req_t2", tenant_id="b"))
    assert service.list_events(tenant_id="a")[1] == 1
    assert service.list_events(tenant_id="b")[1] == 1
    assert service.list_events(tenant_id="c")[1] == 0


def test_get_event():
    service.upsert_event(AuditEventRequest(request_id="req_g1", provider="p"))
    assert service.get_event("req_g1").provider == "p"
    assert service.get_event("req_nope") is None


# ---------------------------------------------------------------------------
# Retention and erasure
# ---------------------------------------------------------------------------


def test_purge_expired_removes_only_old_rows():
    for rid in ("req_old", "req_new"):
        service.upsert_event(AuditEventRequest(request_id=rid))
    with session_scope() as s:
        s.execute(update(RequestAudit).where(RequestAudit.request_id == "req_old")
                  .values(timestamp=datetime.now(timezone.utc) - timedelta(days=40)))
    assert service.purge_expired(retention_days=30) == 1
    assert service.get_event("req_old") is None
    assert service.get_event("req_new") is not None


def test_delete_subject_erases_every_row_for_one_user():
    for i in range(3):
        req, res = inspect(f"req_e{i}", "hello", user_ref="bob")
        service.record_inspection(req, res)
    req, res = inspect("req_e_other", "hello", user_ref="carol")
    service.record_inspection(req, res)
    assert service.delete_subject("bob") == 3
    assert service.count_rows() == 1
    assert service.delete_subject("nobody") == 0
