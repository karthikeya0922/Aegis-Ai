"""Engine and session management.

SQLite is the zero-setup default; PostgreSQL is a `DATABASE_URL` change.
Nothing else in the codebase knows which one is in use.

Schema management: `init_db()` runs `create_all` at startup, which is
idempotent and enough for SQLite development and for the demo. Alembic is
configured alongside (`alembic.ini`, `migrations/`) for deployments that
need controlled upgrades; `create_all` and the initial migration describe
the same schema.
"""

from __future__ import annotations

from contextlib import contextmanager
from functools import lru_cache
from typing import Iterator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)


class Base(DeclarativeBase):
    pass


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def make_engine(url: str | None = None) -> Engine:
    url = url or settings.database_url
    kwargs: dict = {"future": True, "pool_pre_ping": True}
    if _is_sqlite(url):
        # One connection may be used across threads under the ASGI server.
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)

    if _is_sqlite(url):
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine


@lru_cache
def get_engine() -> Engine:
    return make_engine()


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Commit on success, roll back on error, always close."""
    s = get_sessionmaker()()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def init_db(engine: Engine | None = None) -> None:
    """Create any missing tables. Idempotent."""
    from app.audit import models  # noqa: F401 - registers tables on Base

    eng = engine or get_engine()
    Base.metadata.create_all(eng)
    log.info("database ready (%s)", backend_name(eng))


def backend_name(engine: Engine | None = None) -> str:
    eng = engine or get_engine()
    return eng.url.get_backend_name()


def ping(engine: Engine | None = None) -> bool:
    try:
        with (engine or get_engine()).connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:  # noqa: BLE001 - health probe
        log.warning("database ping failed: %s", type(exc).__name__)
        return False
