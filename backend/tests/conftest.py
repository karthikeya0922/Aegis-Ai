"""Shared fixtures.

Two things every test session gets, automatically:

  * a throwaway SQLite database. The engine and sessionmaker are cached
    singletons, so the fixture clears the caches after pointing settings at
    the temp file; anything that touches the database afterwards --
    including the FastAPI TestClient -- uses it.

  * a scratch copy of config/policies.yaml for the policy engine. Phase 15
    made PUT /api/policies write the live file; without this, a contract
    test that exercises PUT would overwrite the repo's policy file (it did,
    once). PRISTINE_POLICY_BODY is the untouched text for tests that need
    to reset to it.
"""

from __future__ import annotations

import shutil

import pytest

PRISTINE_POLICY_BODY: str = ""


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


@pytest.fixture(scope="session", autouse=True)
def _isolated_policy_file(tmp_path_factory):
    global PRISTINE_POLICY_BODY
    from app.security.policy_engine import get_policy_engine

    engine = get_policy_engine()
    original = engine.path
    PRISTINE_POLICY_BODY = original.read_text(encoding="utf-8")
    scratch = tmp_path_factory.mktemp("policies") / "policies.yaml"
    shutil.copy(original, scratch)
    engine.path = scratch
    engine.force_reload()
    yield
    engine.path = original
    engine.force_reload()
