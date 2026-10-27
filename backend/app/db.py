"""Database engine, session factory and FastAPI dependency."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import DATABASE_URL


class Base(DeclarativeBase):
    pass


def _build_engine():
    kwargs: dict = {"pool_pre_ping": True, "future": True}
    if DATABASE_URL.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(DATABASE_URL, **kwargs)

    if DATABASE_URL.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _record):  # pragma: no cover
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _ensure_user_columns() -> None:
    """Add auth columns to tables created before the models grew them.

    `create_all` never alters an existing table, so an instance whose users /
    user_sessions tables predate a column would crash on any listing.  DDL is
    dialect-neutral (SQLite and PostgreSQL both accept it); the admin backfill
    grants admin to the earliest registered account when nobody holds it yet —
    the same rule as the alembic migration, so both schema paths (create_all
    and migrations) converge on identical data.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    # (table, column, dialect-neutral ADD COLUMN) — only for tables that
    # already exist: a fresh create_all builds them straight from the models.
    specs = (
        ("users", "is_admin",
         "ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE"),
        ("user_sessions", "client_ip",
         "ALTER TABLE user_sessions ADD COLUMN client_ip VARCHAR(45)"),
    )
    pending: list[tuple[str, str, str]] = []
    for table, column, ddl in specs:
        if table not in table_names:
            continue
        if column in {col["name"] for col in inspector.get_columns(table)}:
            continue
        pending.append((table, column, ddl))
    if not pending:
        return
    with engine.begin() as conn:
        for _table, _column, ddl in pending:
            conn.execute(text(ddl))
        if any(t == "users" and c == "is_admin" for t, c, _ in pending):
            conn.execute(text(
                "UPDATE users SET is_admin = TRUE "
                "WHERE id = (SELECT id FROM users ORDER BY created_at ASC LIMIT 1) "
                "AND NOT EXISTS (SELECT 1 FROM users WHERE is_admin = TRUE)"))


def init_db() -> None:
    """Create tables.

    TRACE-X ships an Alembic migration for PostgreSQL deployments
    (`alembic upgrade head`); `create_all` keeps local/dev SQLite and tests in
    sync with the models without requiring a running migration history.
    """
    from . import models  # noqa: F401  (ensure models are registered)

    Base.metadata.create_all(bind=engine)
    _ensure_user_columns()