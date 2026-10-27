"""User accounts: password hashing, sessions and login throttling.

Security properties:
  * Passwords are stored as PBKDF2-HMAC-SHA256 with a per-password random
    salt; the work factor is recorded inside the hash string so it can be
    raised later without invalidating existing accounts.  Plaintext is never
    persisted, logged or returned.
  * Session credentials are opaque random bearer tokens.  Only the SHA-256
    digest is persisted, so a database copy cannot be replayed as a live
    credential.  Sessions expire and can be revoked individually.
  * Login attempts are throttled per username+IP (in-memory, per-process —
    documented limitation for multi-worker deployments).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from ..config import (
    LOGIN_LOCKOUT_SECONDS,
    LOGIN_MAX_ATTEMPTS,
    PASSWORD_PBKDF2_ITERATIONS,
    SESSION_HOURS,
)
from ..models import User, UserSession, new_id, utcnow

USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])?$")
MIN_PASSWORD_LENGTH = 8


def is_admin_user(user: User | None) -> bool:
    """True when the account may use the admin section.

    The flag on the row is authoritative; membership of TRACEX_ADMIN_USERS is
    checked at call time so operators can grant admin without a schema edit.
    """
    from .. import config

    if user is None:
        return False
    return bool(user.is_admin) or user.username in config.ADMIN_USERS


class AccountError(ValueError):
    """Domain error with an HTTP-mappable code (invalid_username, ...)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# --- passwords --------------------------------------------------------------

def hash_password(password: str, iterations: int | None = None) -> str:
    """Return ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``."""
    iterations = iterations or PASSWORD_PBKDF2_ITERATIONS
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification; tolerates unknown/corrupt stored formats."""
    try:
        algo, iterations_s, salt_hex, digest_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)


# Pre-computed hash so verifying against a missing username costs the same as
# a real password check (username enumeration via response timing).
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


# --- usernames & users ------------------------------------------------------

def normalize_username(username: str) -> str:
    return (username or "").strip().lower()


def validate_username(username: str) -> str:
    normalized = normalize_username(username)
    if not USERNAME_RE.match(normalized):
        raise AccountError(
            "invalid_username",
            "username must be 3-32 characters: lowercase letters, digits, "
            "'.', '_' or '-', starting and ending with a letter or digit")
    return normalized


def validate_password(password: str) -> None:
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise AccountError(
            "weak_password",
            f"password must be at least {MIN_PASSWORD_LENGTH} characters")


def create_user(db: Session, username: str, password: str,
                display_name: str | None = None) -> User:
    normalized = validate_username(username)
    validate_password(password)
    existing = db.query(User).filter(User.username == normalized).first()
    if existing is not None:
        raise AccountError("username_taken", "that username is already registered")
    from .. import config

    # Bootstrap: the first account ever registered administers this instance
    # (there is no other source of authority on a fresh deployment).
    first_user = db.query(User).count() == 0
    user = User(id=new_id(), username=normalized,
                display_name=(display_name or normalized)[:128],
                password_hash=hash_password(password),
                is_admin=first_user or normalized in config.ADMIN_USERS)
    db.add(user)
    db.flush()
    return user


def authenticate(db: Session, username: str, password: str) -> User | None:
    """Return the user for valid credentials, else None.

    Unknown usernames still perform one PBKDF2 verification (against a dummy
    hash) so response timing does not reveal whether the account exists.
    """
    normalized = normalize_username(username)
    user = (db.query(User)
            .filter(User.username == normalized, User.is_active.is_(True))
            .first())
    if user is None:
        verify_password(password or "", _DUMMY_HASH)
        return None
    if not verify_password(password or "", user.password_hash):
        return None
    return user


# --- sessions ---------------------------------------------------------------

def issue_session(db: Session, user: User, user_agent: str | None = None,
                  client_ip: str | None = None) -> tuple[str, UserSession]:
    """Create a session; returns the raw token (shown once) and the row.

    `user_agent` and `client_ip` describe the device that signed in so the
    admin section can distinguish sessions; neither is ever used for auth.
    """
    token = secrets.token_urlsafe(32)
    session_row = UserSession(
        id=new_id(), user_id=user.id,
        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        expires_at=utcnow() + timedelta(hours=SESSION_HOURS),
        user_agent=(user_agent or "")[:255] or None,
        client_ip=(client_ip or "")[:45] or None,
    )
    db.add(session_row)
    user.last_login_at = utcnow()
    db.flush()
    return token, session_row


def _as_utc(value: datetime | None) -> datetime | None:
    """SQLite (the default deployment) returns naive datetimes; rows are
    written with `utcnow()`, so naive values are UTC.  PostgreSQL returns
    tz-aware values that pass through unchanged."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def resolve_session(db: Session, token: str) -> User | None:
    """Look up the active user for a bearer token, if any."""
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = (db.query(UserSession)
           .filter(UserSession.token_hash == token_hash)
           .first())
    if row is None or row.revoked_at is not None:
        return None
    expires_at = _as_utc(row.expires_at)
    if expires_at is not None and expires_at <= utcnow():
        return None
    user = row.user
    if user is None or not user.is_active:
        return None
    return user


def session_state(row: UserSession) -> str:
    """'live', 'expired' or 'revoked' — for admin listings."""
    if row.revoked_at is not None:
        return "revoked"
    expires_at = _as_utc(row.expires_at)
    if expires_at is not None and expires_at <= utcnow():
        return "expired"
    return "live"


def revoke_user_sessions(db: Session, user_id: str) -> int:
    """Revoke every live session of a user; returns how many were revoked."""
    now = utcnow()
    rows = (db.query(UserSession)
            .filter(UserSession.user_id == user_id,
                    UserSession.revoked_at.is_(None))
            .all())
    revoked = 0
    for row in rows:
        expires_at = _as_utc(row.expires_at)
        if expires_at is not None and expires_at <= now:
            continue  # already dead — nothing to revoke
        row.revoked_at = now
        revoked += 1
    db.flush()
    return revoked


def revoke_session(db: Session, token: str) -> bool:
    """Revoke the session for `token`; True when a live session was revoked."""
    if not token:
        return False
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = (db.query(UserSession)
           .filter(UserSession.token_hash == token_hash,
                   UserSession.revoked_at.is_(None))
           .first())
    if row is None:
        return False
    row.revoked_at = utcnow()
    db.flush()
    return True


# --- login throttle ---------------------------------------------------------
# In-memory per-process: adequate for the single-node local deployment this
# app targets; a multi-worker deployment would need a shared store.

_attempts: dict[str, list[float]] = {}


def _throttle_key(username: str, client: str) -> str:
    return f"{normalize_username(username)}|{client}"


def throttle_retry_after(username: str, client: str) -> int | None:
    """Seconds the caller must wait, or None when they may attempt login."""
    key = _throttle_key(username, client)
    now = time.monotonic()
    window = [t for t in _attempts.get(key, []) if now - t < LOGIN_LOCKOUT_SECONDS]
    _attempts[key] = window
    if len(window) >= LOGIN_MAX_ATTEMPTS:
        return max(1, int(LOGIN_LOCKOUT_SECONDS - (now - window[0])))
    return None


def record_failed_login(username: str, client: str) -> None:
    key = _throttle_key(username, client)
    now = time.monotonic()
    window = [t for t in _attempts.get(key, []) if now - t < LOGIN_LOCKOUT_SECONDS]
    window.append(now)
    _attempts[key] = window


def clear_failed_logins(username: str, client: str) -> None:
    _attempts.pop(_throttle_key(username, client), None)
