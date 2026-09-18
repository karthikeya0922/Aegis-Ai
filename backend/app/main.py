"""Aegis Inspector -- FastAPI application entrypoint.

This service is the absolute authority on whether a prompt is safe. It is
stateless: the same input always yields the same verdict. All session state
(the token vault, the semantic cache) belongs to the Gateway's Redis.

Run: uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import audit, embed, governance, health, inspect
from app.config import settings
from app.utils.ids import request_id as new_request_id
from app.utils.logging import configure_logging, get_logger

configure_logging()
log = get_logger(__name__)

DESCRIPTION = """
The inspection and governance engine behind the **Aegis** Zero-Trust
Responsible AI Gateway.

This service decides whether a prompt may be transmitted, screens model
responses on the way back, and records the platform's decision history. It is
consumed by the Aegis Gateway, never by end clients directly.

### What this service does not claim

* Detection is **heuristic and incomplete**. Prompt-injection defence covers
  known OWASP LLM01 patterns and is bypassable by obfuscation.
* Grounded Response Verification is a **support score**, not a guarantee of
  factual correctness.
* Energy and CO2 figures are **estimates** from configurable assumptions, not
  measurements.
* Audit output is **transaction evidence** supporting a deployer's own
  record-keeping. It is not a conformity assessment and does not establish
  legal compliance.
"""

TAGS_METADATA = [
    {"name": "inspection", "description": "Ingress decisions and egress screening."},
    {"name": "embeddings", "description": "Vectors for the Gateway's semantic cache."},
    {"name": "audit", "description": "Decision history. Write path and read APIs."},
    {"name": "metrics", "description": "Aggregates for the dashboard."},
    {
        "name": "governance",
        "description": (
            "Policy versioning, human review of automated blocks, and measured "
            "detector fairness."
        ),
    },
    {"name": "health", "description": "Subsystem readiness."},
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    log.info(
        "%s v%s starting (phase=%s, env=%s)",
        settings.service_name,
        settings.version,
        health.build_phase(),
        settings.environment,
    )

    # Tables first: the audit write path runs on every /inspect.
    from app.audit.database import init_db

    init_db()

    # Compile the secret patterns now rather than on the first request. Without
    # this the first /inspect pays ~15ms to build 25 regexes, which shows up as
    # a misleading latency spike on the first call of a demo.
    from app.security.secret_scanner import get_scanner

    scanner = get_scanner()
    log.info("secret scanner ready (%d patterns, v%d)", len(scanner.patterns), scanner.version)

    # The PII scanner is warmed unconditionally: loading a spaCy model takes
    # several seconds and must not land on the first request of a demo. If
    # Presidio or the model is absent this returns instantly in regex-only
    # mode, and /api/health reports the degradation.
    from app.security.pii_scanner import get_pii_scanner

    pii = get_pii_scanner()
    pii.warm()
    if pii.degraded:
        log.warning("pii scanner DEGRADED: %s", pii.degraded_reason)
    else:
        log.info("pii scanner ready (engine=%s, spaCy=%s)", pii.engine, pii.spacy_model)

    from app.security.injection import get_detector as get_injection_detector

    inj = get_injection_detector()
    log.info("injection detector ready (%d rules, v%d)", len(inj.ruleset.rules), inj.ruleset.version)

    # Record the policy file as version 1 if history is empty, so the
    # baseline is on file alongside every later change.
    from app.policies.service import bootstrap as bootstrap_policies

    bootstrap_policies()

    from app.security.pipeline import get_pipeline

    pipe = get_pipeline()
    pipe.warm()
    log.info("inspection pipeline ready (routing config v%d)", pipe.routing.version)

    # Embeddings: loading MiniLM takes a few seconds from cache and the
    # first encode pays a further warm-up. Done here so the Gateway's first
    # cache lookup does not. Falls through instantly to hash mode if the
    # package or weights are absent, and health reports that.
    from app.cache.embeddings import get_embedding_service

    emb = get_embedding_service()
    emb.warm()
    if emb.degraded:
        log.warning("embeddings DEGRADED: %s", emb.degraded_reason)
    else:
        log.info("embeddings ready (%s, dim=%d)", emb.model_name, emb.dim)

    # Grounding: the NLI cross-encoder. Warmed here for the same reason as
    # the others; if absent, verification is reported as skipped, never faked.
    from app.verification.grounding import get_verifier

    ver = get_verifier()
    ver.warm()
    if ver.degraded:
        log.warning("grounding DEGRADED (verification will be skipped): %s", ver.degraded_reason)
    else:
        log.info("grounding ready (%s)", ver.model_name)

    from app import hardening

    hardening.warn_if_open()
    stop = asyncio.Event()
    purge_task = asyncio.create_task(hardening.retention_loop(settings.purge_interval_hours, stop))
    log.info("retention scheduler running every %.1fh (AEGIS_AUDIT_RETENTION_DAYS=%d)",
             settings.purge_interval_hours, settings.audit_retention_days)
    yield
    stop.set()
    purge_task.cancel()
    log.info("%s shutting down", settings.service_name)


app = FastAPI(
    title="Aegis Inspector",
    description=DESCRIPTION,
    version=settings.version,
    openapi_tags=TAGS_METADATA,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Request-Id"],
)


@app.middleware("http")
async def limits(request: Request, call_next):
    """Rate limit and deadline. Registered first, so it runs after request_context
    has assigned the request id (Starlette middleware wraps outside-in)."""
    from app.hardening import rate_limit_and_timeout

    return await rate_limit_and_timeout(request, call_next)


@app.middleware("http")
async def request_context(request: Request, call_next):
    """Attach a request ID, enforce the body size limit, add security headers."""
    rid = request.headers.get("X-Request-Id") or new_request_id()
    request.state.request_id = rid

    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.max_request_bytes:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "error": {
                    "code": "REQUEST_TOO_LARGE",
                    "message": (
                        f"Request body exceeds {settings.max_request_bytes} bytes."
                    ),
                    "request_id": rid,
                }
            },
        )

    started = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    response.headers["X-Request-Id"] = rid
    response.headers["X-Inspector-Duration-Ms"] = f"{elapsed_ms:.2f}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    """Contract violations report *where* they occurred, never the payload.

    Echoing the offending body back would defeat the point of a service whose
    job is to keep sensitive values out of logs and error channels.
    """
    fields = [".".join(str(p) for p in e.get("loc", [])) for e in exc.errors()]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "CONTRACT_VIOLATION",
                "message": "Request did not match the documented contract.",
                "fields": fields[:20],
                "request_id": getattr(request.state, "request_id", None),
            }
        },
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", None)
    log.exception("unhandled error request_id=%s type=%s", rid, type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "The inspector failed to process this request.",
                "request_id": rid,
            }
        },
    )


app.include_router(inspect.router)
app.include_router(embed.router)
app.include_router(audit.router)
app.include_router(governance.router)
app.include_router(health.router)

# metrics router carries its own /api/metrics prefix
from app.api import metrics  # noqa: E402

app.include_router(metrics.router)


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {
        "service": settings.service_name,
        "version": settings.version,
        "phase": health.build_phase(),
        "docs": "/docs",
        "openapi": "/openapi.json",
    }
