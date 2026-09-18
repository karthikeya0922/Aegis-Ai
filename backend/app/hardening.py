"""Transport hardening: rate limiting, request timeout, operator auth, and
the retention scheduler.

Scope is stated honestly:

  * Rate limiting is an in-process token bucket keyed by tenant (or client
    address). It protects one Inspector instance from one noisy caller. It
    is NOT a distributed limiter -- with several replicas each has its own
    bucket -- and a shared Redis limiter belongs to the Gateway, which
    already owns Redis.
  * The request timeout bounds how long the Gateway waits. The work on a
    threadpool continues past the deadline; it cannot be cancelled from
    here. The response is a 504 with a request id the operator can find.
  * Operator auth is a shared secret in a header. It gates the endpoints
    that change state for everyone (policy writes, review decisions,
    purge, erasure). RBAC lives in the Gateway; this is the floor beneath
    it. If no secret is configured the endpoints stay open and startup
    logs a warning, so a demo works and a deployment is told.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field

from fastapi import Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


@dataclass
class _Bucket:
    tokens: float
    updated: float


@dataclass
class TokenBucketLimiter:
    per_minute: int
    burst: int
    _buckets: dict[str, _Bucket] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def enabled(self) -> bool:
        return self.per_minute > 0

    def allow(self, key: str, now: float | None = None) -> tuple[bool, float]:
        """Returns (allowed, retry_after_seconds)."""
        if not self.enabled:
            return True, 0.0
        now = time.monotonic() if now is None else now
        rate = self.per_minute / 60.0
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(tokens=float(self.burst), updated=now)
                self._buckets[key] = b
            b.tokens = min(float(self.burst), b.tokens + (now - b.updated) * rate)
            b.updated = now
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return True, 0.0
            return False, round((1.0 - b.tokens) / rate, 2)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


_limiter: TokenBucketLimiter | None = None


def get_limiter() -> TokenBucketLimiter:
    global _limiter
    if _limiter is None:
        _limiter = TokenBucketLimiter(
            per_minute=settings.rate_limit_per_minute, burst=settings.rate_limit_burst
        )
    return _limiter


def rate_limit_key(request: Request) -> str:
    """Tenant header first, then client address. The Gateway sets the header."""
    tenant = request.headers.get("X-Tenant-Id")
    if tenant:
        return f"tenant:{tenant}"
    client = request.client.host if request.client else "unknown"
    return f"addr:{client}"


_EXEMPT_PATHS = frozenset({"/api/health", "/docs", "/redoc", "/openapi.json", "/"})


async def rate_limit_and_timeout(request: Request, call_next):
    """Middleware: 429 when the bucket is empty; 504 when the deadline passes."""
    if request.url.path not in _EXEMPT_PATHS:
        allowed, retry = get_limiter().allow(rate_limit_key(request))
        if not allowed:
            rid = getattr(request.state, "request_id", None)
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(max(1, int(retry + 0.999)))},
                content={"error": {"code": "RATE_LIMITED", "message": "Too many requests for this tenant.",
                                   "retry_after_seconds": retry, "request_id": rid}},
            )

    timeout = settings.request_timeout_seconds
    if timeout <= 0:
        return await call_next(request)
    try:
        return await asyncio.wait_for(call_next(request), timeout=timeout)
    except asyncio.TimeoutError:
        rid = getattr(request.state, "request_id", None)
        log.warning("request %s exceeded %.1fs timeout on %s", rid, timeout, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={"error": {"code": "INSPECTOR_TIMEOUT",
                               "message": f"The inspector did not answer within {timeout:.1f}s.",
                               "request_id": rid}},
        )


# ---------------------------------------------------------------------------
# Operator auth
# ---------------------------------------------------------------------------


def _check(presented: str | None, expected: str | None, role: str) -> None:
    if not expected:
        return  # not configured: open, and startup warned
    if not presented or not _constant_time_eq(presented, expected):
        raise HTTPException(status_code=401, detail=f"{role} token required (X-{role.title()}-Token)")


def _constant_time_eq(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


async def require_reviewer(x_reviewer_token: str | None = Header(default=None)) -> None:
    """Gates review decisions. Set AEGIS_REVIEWER_TOKEN to enable."""
    _check(x_reviewer_token, settings.reviewer_token, "reviewer")


async def require_admin(x_admin_token: str | None = Header(default=None)) -> None:
    """Gates policy writes, purge and erasure. Set AEGIS_ADMIN_TOKEN to enable."""
    _check(x_admin_token, settings.admin_token, "admin")


def warn_if_open() -> None:
    if not settings.reviewer_token:
        log.warning("AEGIS_REVIEWER_TOKEN not set: review decisions are UNAUTHENTICATED")
    if not settings.admin_token:
        log.warning("AEGIS_ADMIN_TOKEN not set: policy writes, purge and erasure are UNAUTHENTICATED")


# ---------------------------------------------------------------------------
# Retention scheduler
# ---------------------------------------------------------------------------


async def retention_loop(interval_hours: float, stop: asyncio.Event) -> None:
    """Run the retention purge on a fixed interval until stopped."""
    from app.audit.service import purge_expired

    interval = max(60.0, interval_hours * 3600.0)
    while not stop.is_set():
        try:
            n = await asyncio.to_thread(purge_expired)
            if n:
                log.info("retention: purged %d row(s)", n)
        except Exception as exc:  # noqa: BLE001 - never let the loop die
            log.error("retention: purge failed: %s", type(exc).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue
