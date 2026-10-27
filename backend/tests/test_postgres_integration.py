"""PostgreSQL integration tests (marker: `pg`).

These run against a LIVE PostgreSQL server instead of the SQLite throwaway
used by the rest of the suite, because several behaviours only exist on
PostgreSQL (Alembic migration chain, `date_trunc` grouping, ILIKE, timestamptz
round-trips). They are deselected by default via `-m "not pg"` in CI's default
run and enabled explicitly:

    TRACEX_TEST_PG_URL=postgresql+psycopg://user:pass@127.0.0.1:5432/postgres \\
        pytest -m pg

A scratch database (tracex_test_<hex>) is created and dropped per session —
never the developer's real database, and the configured URL must point at a
server the tests may create databases on.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.pg

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _configured_url() -> str | None:
    url = os.environ.get("TRACEX_TEST_PG_URL", "").strip()
    if url:
        return url
    host = os.environ.get("POSTGRES_HOST", "").strip()
    user = os.environ.get("POSTGRES_USER", "").strip()
    password = os.environ.get("POSTGRES_PASSWORD", "").strip()
    if host and user and password:
        port = os.environ.get("POSTGRES_PORT", "5432")
        return (f"postgresql+psycopg://{user}:{password}@{host}:{port}/"
                f"{os.environ.get('POSTGRES_DB', 'postgres')}")
    return None


def _admin_url(fallback: str) -> str:
    """Connection used only to CREATE/DROP the scratch database.

    The application role is intentionally least-privilege (no CREATEDB), so
    superuser credentials come from TRACEX_TEST_PG_ADMIN_URL. CI's postgres
    image makes its POSTGRES_USER a superuser, so there the normal URL works
    as its own admin URL.
    """
    return os.environ.get("TRACEX_TEST_PG_ADMIN_URL", "").strip() or fallback


@pytest.fixture(scope="session")
def pg_url():
    """URL of a reachable server + a per-session scratch database."""
    base = _configured_url()
    if not base:
        pytest.skip("no PostgreSQL configured (set TRACEX_TEST_PG_URL or POSTGRES_*)")

    from sqlalchemy import create_engine, text
    from sqlalchemy.pool import NullPool

    # CREATE/DROP DATABASE cannot run inside a transaction block, and
    # SQLAlchemy 2.x autobegins one on connect — force autocommit.
    server = create_engine(_admin_url(base), poolclass=NullPool,
                           isolation_level="AUTOCOMMIT", future=True)
    scratch = f"tracex_test_{uuid.uuid4().hex[:12]}"
    try:
        with server.connect() as conn:
            conn.execute(text("SELECT 1"))
            conn.execute(text(f'CREATE DATABASE "{scratch}"'))
    except Exception as exc:  # server unreachable / no CREATE DATABASE rights
        server.dispose()
        message = str(exc)
        if "permission denied" in message or "InsufficientPrivilege" in message:
            pytest.skip(
                "the configured role cannot CREATE DATABASE (expected for the "
                "least-privilege app role); set TRACEX_TEST_PG_ADMIN_URL to "
                "superuser credentials — CI's postgres image needs no admin URL")
        pytest.skip(f"PostgreSQL not reachable for integration tests: {message}")

    head, _, tail = base.rpartition("/")
    url = f"{head}/{scratch}?{tail.split('?')[1]}" if "?" in tail else f"{head}/{scratch}"
    yield url

    try:
        with server.connect() as conn:
            # pg 14+: FORCE keeps the drop from failing on lingering connections.
            conn.execute(text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{scratch}' AND pid <> pg_backend_pid()"))
            conn.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
    except Exception:
        pass
    finally:
        server.dispose()


@pytest.fixture(scope="session")
def pg_engine(pg_url):
    """Schema-created engine on the scratch database (models, not migrations)."""
    from sqlalchemy import create_engine

    engine = create_engine(pg_url, pool_pre_ping=True, future=True)
    from app.db import Base
    from app import models  # noqa: F401  register mappings

    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def pg_db(pg_engine):
    from sqlalchemy.orm import Session

    session = Session(pg_engine, expire_on_commit=False, future=True)
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# ---------------------------------------------------------------------------
# Migration chain
# ---------------------------------------------------------------------------

def test_alembic_upgrade_head_applies_cleanly(pg_url):
    """`alembic upgrade head` must run the full chain on a fresh PG database."""
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect, text

    cfg = Config(os.path.join(BACKEND, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND, "alembic"))
    cfg.set_main_option("sqlalchemy.url", pg_url)
    command.upgrade(cfg, "head")

    engine = create_engine(pg_url, future=True)
    try:
        tables = set(inspect(engine).get_table_names())
        for expected in ("investigations", "evidence_sources", "events",
                         "analysis_runs", "findings", "suspicion_chains",
                         "audit_logs", "graph_nodes", "graph_edges", "alembic_version"):
            assert expected in tables, f"missing table after upgrade: {expected}"

        with engine.connect() as conn:
            # the auth/owner migration must be part of head
            cols = {c["name"] for c in inspect(engine).get_columns("investigations")}
            assert "owner" in cols
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version, "alembic_version is empty after upgrade"
    finally:
        engine.dispose()


def test_alembic_head_has_no_model_drift(pg_url):
    """`alembic check` — models and migrations must agree (no pending ops)."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(os.path.join(BACKEND, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND, "alembic"))
    cfg.set_main_option("sqlalchemy.url", pg_url)
    command.upgrade(cfg, "head")
    # raises CommandError when new operations would be needed
    command.check(cfg)


# ---------------------------------------------------------------------------
# Core flows on PostgreSQL
# ---------------------------------------------------------------------------

def test_ingest_analyse_timeline_roundtrip_on_postgres(pg_db, monkeypatch):
    """Demo ingestion + detection + timeline + dashboard series on live PG.

    Also regression-covers the PostgreSQL-only `date_trunc` GroupingError in
    the dashboard activity series (SQLite inlines literals so it never
    reproduced there).
    """
    from app.api.data import _activity_series
    from app.datasets import scenario_by_id
    from app.demo import create_demo_investigation
    from app.models import Event, Finding, SuspicionChain
    from app.services.timeline import TimelineFilter, facets, query_events

    scenario = scenario_by_id("af_chain")
    assert scenario is not None
    inv = create_demo_investigation(pg_db, scenario, analyse=True)

    events = pg_db.query(Event).filter(Event.investigation_id == inv.id).count()
    assert events > 0

    fired = {f.rule_id for f in pg_db.query(Finding)
             .filter(Finding.investigation_id == inv.id)}
    assert set(scenario.expected_rules) <= fired, (
        f"PG run missed declared rules: {set(scenario.expected_rules) - fired}")

    chains = {c.pattern_id for c in pg_db.query(SuspicionChain)
              .filter(SuspicionChain.investigation_id == inv.id)}
    assert set(scenario.expected_chains) <= chains

    rows, total = query_events(pg_db, inv.id, TimelineFilter(limit=100))
    assert total == events
    timed = [e.timestamp for e in rows if e.timestamp is not None]
    assert timed == sorted(timed), "timeline not ascending on PostgreSQL"

    data = facets(pg_db, inv.id, TimelineFilter())
    assert data.get("event_types") is not None

    series = _activity_series(pg_db, inv.id)
    assert isinstance(series, list) and series, (
        "dashboard activity series empty — date_trunc grouping failed on PG")
    assert all("bucket" in b and "count" in b for b in series)


def test_timestamptz_roundtrip_and_undated_handling(pg_db):
    """Timestamps survive the PG timestamptz round-trip; undated rows sort last."""
    from datetime import datetime, timezone

    from app.models import Event, Investigation, new_id
    from app.services.timeline import TimelineFilter, query_events

    inv = Investigation(id=new_id(), name="TZ case", case_id=f"PG-TZ-{uuid.uuid4().hex[:6]}",
                        status="open", origin="user", analysis_config={})
    pg_db.add(inv)
    pg_db.flush()
    base = datetime(2026, 3, 2, 9, 0, 0, tzinfo=timezone.utc)
    for i in range(3):
        pg_db.add(Event(id=new_id(), investigation_id=inv.id,
                        timestamp=base.replace(hour=9 + i),
                        timestamp_raw=base.replace(hour=9 + i).isoformat(),
                        event_type="file_access", source_type="structured",
                        description=f"access {i}", seq=i + 1))
    pg_db.add(Event(id=new_id(), investigation_id=inv.id, timestamp=None,
                    timestamp_raw=None, timestamp_precision="unknown",
                    timestamp_confidence="none", event_type="unknown",
                    source_type="structured", description="undated", seq=99))
    pg_db.commit()

    rows, total = query_events(pg_db, inv.id, TimelineFilter(limit=50))
    assert total == 4
    assert rows[-1].timestamp is None, "undated event must sort last on PG"
    stored = pg_db.query(Event).filter(Event.investigation_id == inv.id,
                                       Event.timestamp.isnot(None)).all()
    for e in stored:
        assert e.timestamp.tzinfo is not None, "timestamptz lost tzinfo on read"


def test_owner_filtering_and_ilike_search_on_postgres(pg_db):
    """The auth owner column filters listings; ILIKE search works on PG."""
    from app.models import Investigation, new_id

    owned = Investigation(id=new_id(), name="Alice secret case", case_id="PG-OWN-1",
                          status="open", origin="user", owner="alice",
                          analysis_config={})
    shared = Investigation(id=new_id(), name="Shared case", case_id="PG-OWN-2",
                           status="open", origin="user", owner=None,
                           analysis_config={})
    pg_db.add_all([owned, shared])
    pg_db.commit()

    for actor in ("alice", "bob"):
        visible = [i.id for i in pg_db.query(Investigation)
                   .filter((Investigation.owner.is_(None))
                           | (Investigation.owner == actor)).all()]
        assert owned.id in visible if actor == "alice" else owned.id not in visible
        assert shared.id in visible, "unowned investigations stay visible to all"

    hit = pg_db.query(Investigation).filter(
        Investigation.name.ilike("%secret%")).all()
    assert [i.id for i in hit] == [owned.id]


def test_evaluation_harness_completes(pg_db):
    """The A/B/C evaluation harness runs to completion (uses its own sessions)."""
    from app.evaluation import run_evaluation

    result = run_evaluation(["normal", "deletion"], ["A", "B", "C"])
    assert not result.get("error"), result.get("error")
    assert len(result.get("configurations", [])) == 3
