"""Phase 16 -- hardening.

The load-bearing test is the logger one: a credential passed to the logger,
on any handler, in any logger, must not be observable. Then the transport
limits (429, 504), operator auth (401 / 200), and the retention scheduler.
"""

from __future__ import annotations

import asyncio
import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import hardening
from app.hardening import TokenBucketLimiter, rate_limit_and_timeout
from app.utils.logging import install_redacting_record_factory, scrub


def _joined(*parts: str) -> str:
    return "".join(parts)


# ---------------------------------------------------------------------------
# The logger cannot leak
# ---------------------------------------------------------------------------

LEAKS = [
    _joined("AKIA", "IOSFODNN7EXAMPLE"),
    _joined("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"),
    _joined("sk-", "abcdefghijklmnopqrstuvwxyz1234567890"),
    _joined("xoxb-", "123456789012-abcdefghijklmnop"),
    _joined("postgres://admin:", "hunter2secret", "@db.internal/aegis"),
]


@pytest.mark.parametrize("secret", LEAKS)
def test_record_factory_scrubs_before_any_handler(caplog, secret):
    """caplog's handler is not our stdout handler. If the scrub only lived on
    the stdout handler, caplog would see the raw secret. It must not."""
    install_redacting_record_factory()
    log = logging.getLogger("aegis.test.leak")
    with caplog.at_level(logging.INFO, logger="aegis.test.leak"):
        log.info("token is %s", secret)
        log.info("inline %s" % secret)
        log.info("dict style %(k)s", {"k": secret})
    for rec in caplog.records:
        assert secret not in rec.getMessage()
        assert secret not in str(rec.msg)
    assert secret not in caplog.text
    assert "[REDACTED" in caplog.text


def test_scrub_leaves_ordinary_text_alone():
    assert scrub("The cache hit rate was 0.71 on tenant acme") == "The cache hit rate was 0.71 on tenant acme"


def test_password_in_uri_is_scrubbed_but_user_is_kept():
    out = scrub(_joined("postgres://admin:", "hunter2secret", "@db.internal/aegis"))
    assert out == "postgres://admin:[REDACTED_PASSWORD]@db.internal/aegis"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def test_token_bucket_refills_at_rate():
    lim = TokenBucketLimiter(per_minute=60, burst=2)  # 1 token/s
    assert lim.allow("t", now=0.0) == (True, 0.0)
    assert lim.allow("t", now=0.0) == (True, 0.0)
    ok, retry = lim.allow("t", now=0.0)
    assert not ok and retry == 1.0
    assert lim.allow("t", now=1.0)[0]           # one token back
    assert lim.allow("other", now=1.0)[0]        # buckets are per key


def test_disabled_limiter_always_allows():
    lim = TokenBucketLimiter(per_minute=0, burst=0)
    assert all(lim.allow("x")[0] for _ in range(100))


def test_429_on_live_app_with_retry_after(monkeypatch):
    from app.main import app

    monkeypatch.setattr(hardening, "_limiter", TokenBucketLimiter(per_minute=6, burst=2))  # 0.1 tok/s: a slow first request cannot refill
    c = TestClient(app)
    body = {"request_id": "req_rl", "messages": [{"role": "user", "content": "hi"}]}
    h = {"X-Tenant-Id": "noisy"}
    assert c.post("/inspect", json=body, headers=h).status_code == 200
    assert c.post("/inspect", json=body, headers=h).status_code == 200
    r = c.post("/inspect", json=body, headers=h)
    assert r.status_code == 429
    assert r.headers["Retry-After"].isdigit()
    assert r.json()["error"]["code"] == "RATE_LIMITED"
    # another tenant is unaffected, and health is exempt
    assert c.post("/inspect", json=body, headers={"X-Tenant-Id": "quiet"}).status_code == 200
    assert c.get("/api/health", headers=h).status_code == 200


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------


def test_504_when_deadline_passes(monkeypatch):
    slow = FastAPI()

    @slow.middleware("http")
    async def mw(request, call_next):
        return await rate_limit_and_timeout(request, call_next)

    @slow.get("/slow")
    async def _slow():
        await asyncio.sleep(0.5)
        return {"ok": True}

    @slow.get("/fast")
    async def _fast():
        return {"ok": True}

    monkeypatch.setattr(hardening.settings, "request_timeout_seconds", 0.05)
    monkeypatch.setattr(hardening, "_limiter", TokenBucketLimiter(per_minute=0, burst=0))
    c = TestClient(slow)
    r = c.get("/slow")
    assert r.status_code == 504 and r.json()["error"]["code"] == "INSPECTOR_TIMEOUT"
    assert c.get("/fast").status_code == 200


# ---------------------------------------------------------------------------
# Operator auth
# ---------------------------------------------------------------------------


def test_admin_endpoints_open_when_unconfigured(monkeypatch):
    from app.main import app

    monkeypatch.setattr(hardening.settings, "admin_token", None)
    assert TestClient(app).post("/api/audit/purge").status_code == 200


def test_admin_endpoints_require_token_when_configured(monkeypatch):
    from app.main import app

    monkeypatch.setattr(hardening.settings, "admin_token", "adm-secret")
    c = TestClient(app)
    assert c.post("/api/audit/purge").status_code == 401
    assert c.post("/api/audit/purge", headers={"X-Admin-Token": "wrong"}).status_code == 401
    assert c.post("/api/audit/purge", headers={"X-Admin-Token": "adm-secret"}).status_code == 200
    assert c.post("/api/audit/erase-subject", json={"user_ref": "u1"}).status_code == 401
    assert c.put("/api/policies", json={"body": {}, "actor": "x", "reason": "y"}).status_code == 401
    assert c.post("/api/policies/rollback/1").status_code == 401
    # reads stay open
    assert c.get("/api/policies").status_code == 200


def test_review_decision_requires_reviewer_token(monkeypatch):
    from app.main import app

    monkeypatch.setattr(hardening.settings, "reviewer_token", "rev-secret")
    c = TestClient(app)
    cr = c.post("/api/reviews", json={"request_id": "req_auth_rev", "original_decision": "BLOCK",
                                       "user_justification": "false positive"})
    assert cr.status_code == 201
    rid = cr.json()["review"]["id"]
    dec = {"approve": True, "reviewer_ref": "alice", "reviewer_note": "ok"}
    assert c.post(f"/api/reviews/{rid}/decision", json=dec).status_code == 401
    r = c.post(f"/api/reviews/{rid}/decision", json=dec, headers={"X-Reviewer-Token": "rev-secret"})
    assert r.status_code == 200
    # reading reviews needs no token
    assert c.get("/api/reviews").status_code == 200


def test_warn_if_open_logs_when_unconfigured(monkeypatch, caplog):
    monkeypatch.setattr(hardening.settings, "reviewer_token", None)
    monkeypatch.setattr(hardening.settings, "admin_token", None)
    with caplog.at_level(logging.WARNING, logger="app.hardening"):
        hardening.warn_if_open()
    assert "UNAUTHENTICATED" in caplog.text


# ---------------------------------------------------------------------------
# Retention scheduler
# ---------------------------------------------------------------------------


def test_retention_loop_purges_then_stops(monkeypatch):
    calls: list[int] = []

    def fake_purge():
        calls.append(1)
        return 3

    import app.audit.service as svc

    monkeypatch.setattr(svc, "purge_expired", fake_purge)

    async def run():
        stop = asyncio.Event()
        task = asyncio.create_task(hardening.retention_loop(0.0, stop))  # clamps to 60s
        await asyncio.sleep(0.1)
        stop.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(run())
    assert calls == [1]


def test_retention_loop_survives_a_failing_purge(monkeypatch):
    import app.audit.service as svc

    def boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(svc, "purge_expired", boom)

    async def run():
        stop = asyncio.Event()
        task = asyncio.create_task(hardening.retention_loop(0.0, stop))
        await asyncio.sleep(0.1)
        stop.set()
        await asyncio.wait_for(task, timeout=2)  # returns cleanly, did not raise

    asyncio.run(run())
