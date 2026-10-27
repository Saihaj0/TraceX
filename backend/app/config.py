"""TRACE-X application configuration.

All secrets and environment-specific values come from environment variables.
No credentials are stored in source code.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import quote_plus

BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = BACKEND_DIR.parent
DATA_DIR = Path(os.environ.get("TRACEX_DATA_DIR", str(BACKEND_DIR / "data")))
EVIDENCE_DIR = DATA_DIR / "evidence"
REPORT_DIR = DATA_DIR / "reports"

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# TRACE-X is developed against PostgreSQL for persistent storage.  When
# POSTGRES_* variables are supplied the application uses PostgreSQL.
# Otherwise it falls back to a local SQLite database so the application remains
# usable on machines without a PostgreSQL server (documented limitation).
# ---------------------------------------------------------------------------

DB_HOST = os.environ.get("POSTGRES_HOST", "")
DB_PORT = os.environ.get("POSTGRES_PORT", "5432")
DB_USER = os.environ.get("POSTGRES_USER", "")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "")
DB_NAME = os.environ.get("POSTGRES_DB", "tracex")

if os.environ.get("DATABASE_URL"):
    DATABASE_URL = os.environ["DATABASE_URL"]
elif DB_HOST and DB_USER and DB_PASSWORD:
    DATABASE_URL = (
        f"postgresql+psycopg://{quote_plus(DB_USER)}:{quote_plus(DB_PASSWORD)}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
else:
    DATABASE_URL = f"sqlite:///{BACKEND_DIR / 'tracex.db'}"

# ---------------------------------------------------------------------------
# API / application
# ---------------------------------------------------------------------------
API_PREFIX = os.environ.get("TRACEX_API_PREFIX", "/api")
APP_ENV = os.environ.get("TRACEX_ENV", "development")
# TRACE-X currently runs on a trusted local machine and has no user accounts.
AUTH_ENABLED = os.environ.get("TRACEX_AUTH_ENABLED", "false").lower() == "true"
DEFAULT_ACTOR = os.environ.get("TRACEX_ACTOR", "investigator")
# API-key auth (item: auth + multi-user). Format: "name:token,name2:token2".
# Tokens are compared in constant time and never logged or returned by the API.
API_KEYS: dict[str, str] = {}
for _pair in filter(None, (p.strip() for p in os.environ.get("TRACEX_API_KEYS", "").split(","))):
    _name, _sep, _token = _pair.partition(":")
    if _sep and _name.strip() and _token.strip():
        API_KEYS[_name.strip()] = _token.strip()
if AUTH_ENABLED and not API_KEYS:
    raise RuntimeError(
        "TRACEX_AUTH_ENABLED=true requires TRACEX_API_KEYS (\"name:token,name2:token2\")"
    )

# User accounts (signup / sign-in).  When enabled every API request outside
# the public auth endpoints must carry a valid session bearer token; the
# signed-in username becomes the audit actor and the owner of new
# investigations.  Read dynamically so tests can toggle it per-case.
USER_AUTH_ENABLED = os.environ.get("TRACEX_USER_AUTH_ENABLED", "true").lower() == "true"
SESSION_HOURS = int(os.environ.get("TRACEX_SESSION_HOURS", "24"))
# Session credentials travel in an HttpOnly cookie so page JavaScript can never
# read them (no localStorage, no Authorization header from the web UI).
SESSION_COOKIE_NAME = os.environ.get("TRACEX_SESSION_COOKIE", "tracex_session")
# Usernames that always count as administrators, comma-separated.  The first
# registered account is also made an admin (see services/accounts.create_user).
ADMIN_USERS: set[str] = {
    u.strip().lower()
    for u in os.environ.get("TRACEX_ADMIN_USERS", "").split(",")
    if u.strip()
}
# Login brute-force throttle (in-memory, per-process).
LOGIN_MAX_ATTEMPTS = int(os.environ.get("TRACEX_LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("TRACEX_LOGIN_LOCKOUT_SECONDS", "300"))
# PBKDF2-HMAC-SHA256 work factor for password hashing.
PASSWORD_PBKDF2_ITERATIONS = int(os.environ.get("TRACEX_PBKDF2_ITERATIONS", "390000"))

# Analysis defaults (per-investigation overrides live in analysis_config)
DEFAULT_ANALYSIS_CONFIG: dict = {
    # Maximum separation between two events for TEMPORALLY_NEAR / chain linking.
    "chain_window_hours": 72,
    # Window used when a rule links "activity" to "evidence loss".
    "activity_window_hours": 24,
    # Number of deletions inside the mass-deletion window that are suspicious.
    "mass_deletion_threshold": 8,
    "mass_deletion_window_hours": 2,
    # A gap between audit-bearing events larger than this is a logging gap.
    "logging_gap_hours": 12,
    # Clock-drift threshold (seconds) used by timestamp consistency checks.
    "clock_drift_seconds": 300,
    # Maximum number of nodes returned by the graph endpoint (cap for the UI).
    "graph_max_nodes": 600,
}
ENGINE_VERSION = "1.0.0"
RULES_VERSION = "1.0.0"
PARSERS_VERSION = "1.0.0"


def ensure_directories() -> None:
    for path in (DATA_DIR, EVIDENCE_DIR, REPORT_DIR):
        path.mkdir(parents=True, exist_ok=True)

