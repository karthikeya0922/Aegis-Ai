"""Shared fixtures.

Every test session gets its own throwaway SQLite database. The engine and
sessionmaker are cached singletons, so the fixture clears the caches after
pointing settings at the temp file; anything that touches the database
afterwards -- including the FastAPI TestClient in test_contract -- uses it.
"""

from __future__ import annotations

import pytest


@pytest.fixture(scope="session", autouse=True)
def _isolated_database(tmp_path_factory):
    from app import config
    from app.audit import database

    path = tmp_path_factory.mktemp("db") / "aegis_test.db"
    config.settings.database_url = f"sqlite:///{path.as_posix()}"
    database.get_engine.cache_clear()
    database.get_sessionmaker.cache_clear()
    database.init_db()
    yield
    database.get_engine().dispose()
