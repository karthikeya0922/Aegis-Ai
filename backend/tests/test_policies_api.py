"""Phase 15 -- policy versioning.

The engine is pointed at a scratch copy of config/policies.yaml for the
whole session (tests/conftest.py) so no test can mutate the repo's file. What these pin: every change
is an immutable row, the engine serves the new rules immediately, an
invalid document changes nothing, rollback is itself a new version, and
the audit row records the version that was in force.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.audit import service as audit
from app.audit.database import session_scope
from app.audit.models import PolicyVersion, RequestAudit
from app.contracts.common import Decision, Message
from app.contracts.inspect import InspectRequest
from app.policies import service as policies
from app.security.pipeline import get_pipeline
from app.security.policy_engine import get_policy_engine

PII_TEXT = "mail john@example.com"


@pytest.fixture(autouse=True)
def _clean_history():
    """Every test starts with empty history and the PRISTINE policy at v1.

    The engine already points at a scratch copy (tests/conftest.py); this
    resets that copy's contents rather than whatever the previous test left.
    """
    import tests.conftest as ct

    with session_scope() as s:
        s.query(PolicyVersion).delete()
        s.query(RequestAudit).delete()
    engine = get_policy_engine()
    engine.path.write_text(policies._stamp_version(ct.PRISTINE_POLICY_BODY, 1), encoding="utf-8")
    engine.force_reload()
    yield


def body_with(action_for_pii: str) -> str:
    return get_policy_engine().path.read_text(encoding="utf-8").replace(
        "      pii:\n        action: sanitize", f"      pii:\n        action: {action_for_pii}", 1
    )


def decide(rid: str = "req_pv") -> Decision:
    req = InspectRequest(request_id=rid, messages=[Message(role="user", content=PII_TEXT)])
    res = get_pipeline().run(req)
    audit.record_inspection(req, res)
    return res.decision


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


def test_bootstrap_records_baseline_once():
    assert policies.version_count() == 0
    assert policies.bootstrap() is True
    assert policies.version_count() == 1
    assert policies.bootstrap() is False
    h = policies.history()
    assert h[0].version == 1 and h[0].diff_summary == "initial"


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


def test_update_creates_a_new_version_and_the_engine_serves_it():
    policies.bootstrap()
    assert decide("req_before") is Decision.SANITIZE

    res = policies.update(body_with("block"), author_ref="ops@corp", note="block PII for audit week")
    assert res.version == 2
    assert "version: 2" in res.yaml_body
    assert policies.version_count() == 2

    # in force immediately, and the audit row records which version decided
    assert decide("req_after") is Decision.BLOCK
    with session_scope() as s:
        row = s.execute(select(RequestAudit).where(RequestAudit.request_id == "req_after")).scalar_one()
        assert row.policy_version == 2


def test_first_update_on_empty_history_records_the_baseline_first():
    """A fresh deployment's first PUT must leave v1 on file to roll back to."""
    assert policies.version_count() == 0
    res = policies.update(body_with("block"), author_ref=None, note="first change ever")
    assert res.version == 2
    assert [h.version for h in policies.history()] == [2, 1]
    assert "action: sanitize" in policies.get_version_body(1)
    assert policies.rollback(1, author_ref=None, note=None).version == 3


def test_stamped_version_replaces_whatever_the_author_wrote():
    policies.bootstrap()
    submitted = body_with("block").replace("version: 1", "version: 999", 1)
    res = policies.update(submitted, author_ref=None, note=None)
    assert res.version == 2 and "version: 999" not in res.yaml_body


def test_invalid_document_changes_nothing():
    policies.bootstrap()
    before = get_policy_engine().path.read_text(encoding="utf-8")
    with pytest.raises(policies.PolicyInvalid, match="default_profile"):
        policies.update("version: 1\ndefault_profile: nope\nprofiles: {}\n", author_ref=None, note=None)
    assert policies.version_count() == 1
    assert get_policy_engine().path.read_text(encoding="utf-8") == before
    assert decide() is Decision.SANITIZE


def test_rows_are_immutable_history():
    policies.bootstrap()
    policies.update(body_with("block"), author_ref="a", note="v2")
    policies.update(body_with("warn"), author_ref="b", note="v3")
    with session_scope() as s:
        rows = s.execute(select(PolicyVersion).order_by(PolicyVersion.version)).scalars().all()
        assert [r.version for r in rows] == [1, 2, 3]
        assert "action: sanitize" in rows[0].yaml_body
        assert "action: block" in rows[1].yaml_body
        assert "action: warn" in rows[2].yaml_body


def test_author_is_hashed():
    policies.bootstrap()
    policies.update(body_with("block"), author_ref="ops@corp.example", note=None)
    with session_scope() as s:
        row = s.execute(select(PolicyVersion).where(PolicyVersion.version == 2)).scalar_one()
        assert row.author_ref_hash and "ops@corp" not in row.author_ref_hash


# ---------------------------------------------------------------------------
# Diff summary
# ---------------------------------------------------------------------------


def test_diff_summary_names_the_changed_rule():
    policies.bootstrap()
    policies.update(body_with("block"), author_ref=None, note=None)
    h = policies.history()
    assert h[0].version == 2
    assert "default.pii: sanitize->block" in h[0].diff_summary
    assert "~1 changed" in h[0].diff_summary


def test_diff_summary_counts_added_and_removed():
    base = "version: 1\ndefault_profile: d\nprofiles:\n  d:\n    rules:\n      pii: {action: sanitize}\n"
    more = base + "      secrets: {action: block}\n"
    assert "+1 rules" in policies.diff_summary(base, more)
    assert "-1 rules" in policies.diff_summary(more, base)
    assert "added: d.secrets" in policies.diff_summary(base, more)


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


def test_rollback_is_a_new_version_not_a_rewrite():
    policies.bootstrap()
    policies.update(body_with("block"), author_ref=None, note="tighten")
    assert decide("req_x1") is Decision.BLOCK

    res = policies.rollback(1, author_ref="ops", note="too noisy")
    assert res.version == 3
    assert policies.version_count() == 3
    assert decide("req_x2") is Decision.SANITIZE
    h = policies.history()
    assert h[0].version == 3 and h[0].note.startswith("rollback to v1")
    # v2 is still on file, untouched
    assert "action: block" in policies.get_version_body(2)


def test_rollback_to_unknown_version():
    policies.bootstrap()
    with pytest.raises(policies.PolicyVersionNotFound):
        policies.rollback(42, author_ref=None, note=None)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def test_api_lifecycle():
    from fastapi.testclient import TestClient

    from app.main import app

    c = TestClient(app)
    policies.bootstrap()

    cur = c.get("/api/policies").json()
    assert cur["version"] == 1 and "prompt_injection:" in cur["yaml_body"]

    r = c.put("/api/policies", json={"yaml_body": body_with("block"), "author_ref": "ops", "note": "api"})
    assert r.status_code == 200 and r.json()["version"] == 2

    bad = c.put("/api/policies", json={"yaml_body": "version: 1\ndefault_profile: nope\nprofiles: {}\n"})
    assert bad.status_code == 422 and "default_profile" in bad.text

    hist = c.get("/api/policies/history").json()["versions"]
    assert [v["version"] for v in hist] == [2, 1]

    v1 = c.get("/api/policies/versions/1").json()
    assert v1["version"] == 1 and "action: sanitize" in v1["yaml_body"]
    assert c.get("/api/policies/versions/99").status_code == 404

    rb = c.post("/api/policies/rollback/1", json={"note": "revert"})
    assert rb.status_code == 200 and rb.json()["version"] == 3
    assert c.get("/api/policies").json()["version"] == 3
    assert c.post("/api/policies/rollback/99").status_code == 404
