"""Shared fixtures.

Environment variables are set BEFORE importing the app so tests always run
against a throwaway SQLite database and a temporary data directory — the real
POSTGRES_*/DATABASE_URL of the developer machine is never touched.
"""

from __future__ import annotations

import os
import pathlib
import tempfile
import uuid

_TMP = pathlib.Path(tempfile.mkdtemp(prefix="tracex-test-"))
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP}/test.db"
os.environ["TRACEX_DATA_DIR"] = str(_TMP / "data")
# The domain suite exercises trusted-local mode (no login screens, shared
# cases).  tests/test_accounts.py flips TRACEX_USER_AUTH_ENABLED on per-test
# to exercise the sign-in flow itself.
os.environ["TRACEX_USER_AUTH_ENABLED"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _schema():
    """Create tables once per session, regardless of which fixtures a test uses."""
    from app.db import init_db

    init_db()


@pytest.fixture(scope="session")
def client() -> TestClient:
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _clean_session_cookie(client):
    """The client is session-scoped, so its cookie jar spans tests; with
    cookie-based sessions one test's login must never authenticate the next."""
    client.cookies.clear()
    yield
    client.cookies.clear()


@pytest.fixture()
def db():
    from app.db import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture()
def new_investigation(client):
    """Create an investigation through the API and return its payload."""

    def _create(name: str = "Case", case_id: str | None = None, **extra) -> dict:
        payload = {"name": name, "case_id": case_id or f"CASE-{uuid.uuid4().hex[:8]}"}
        payload.update(extra)
        response = client.post("/api/investigations", json=payload)
        assert response.status_code in (200, 201), response.text
        body = response.json()
        body["_case_id"] = payload["case_id"]
        return body

    return _create


@pytest.fixture()
def demo(db):
    """Create a labelled synthetic investigation straight from app.datasets."""

    def _make(scenario_id: str, analyse: bool = True) -> str:
        from app.datasets import scenario_by_id
        from app.demo import create_demo_investigation

        scenario = scenario_by_id(scenario_id)
        assert scenario is not None, f"unknown scenario {scenario_id}"
        investigation = create_demo_investigation(db, scenario, analyse=analyse)
        return investigation.id

    return _make