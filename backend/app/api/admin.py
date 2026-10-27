"""Admin endpoints: registered-user directory and session revocation.

Access policy
  * With user sessions on, only an account flagged admin (first registered
    account or TRACEX_ADMIN_USERS) may call these routes — everyone else gets
    403 `not_admin`.
  * In API-key mode the key operator is the admin; in trusted-local mode the
    local caller is (there is no other authority on a single-user instance).
  * Responses never expose password hashes or raw tokens: sessions are shown
    by id, timestamps, user agent, client IP and state only.

Every revocation is written to the audit trail.
"""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import config
from ..auth import _extract_token, current_actor
from ..db import get_db
from ..models import User, UserSession, utcnow
from ..services.accounts import is_admin_user, revoke_user_sessions, session_state
from ..services.ingest import audit

router = APIRouter(prefix="/admin", tags=["admin"])


def require_admin(request: Request, db: Session = Depends(get_db)) -> User | None:
    """Gate for every admin route; returns the signed-in admin user if any."""
    user = getattr(request.state, "user", None)
    if user is not None:
        if not is_admin_user(user):
            raise HTTPException(status_code=403, detail={
                "code": "not_admin",
                "message": "this account does not have administrator rights"})
        return user
    # No session on the request.  With user auth on, the middleware guard has
    # already rejected unauthenticated requests before routing, so reaching
    # here means API-key mode or trusted-local mode.
    if config.USER_AUTH_ENABLED:
        raise HTTPException(status_code=401, detail={
            "code": "auth_required", "message": "sign in to continue"})
    if config.AUTH_ENABLED:
        current_actor(request)  # validates the API key; 401s when invalid
    return None  # trusted-local operator (or API-key operator)


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def _session_payload(row: UserSession, caller_hash: str | None) -> dict:
    return {
        "id": row.id,
        "created_at": _iso(row.created_at),
        "expires_at": _iso(row.expires_at),
        "revoked_at": _iso(row.revoked_at),
        "user_agent": row.user_agent,
        "client_ip": row.client_ip,
        "status": session_state(row),
        "is_current": bool(caller_hash) and caller_hash == row.token_hash,
    }


def _caller_hash(request: Request) -> str | None:
    token = _extract_token(request)
    if not token:
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _get_session_row(db: Session, session_id: str) -> UserSession:
    row = db.get(UserSession, session_id)
    if row is None:
        raise HTTPException(status_code=404, detail={
            "code": "session_not_found", "message": "no such session"})
    return row


def _get_user_row(db: Session, user_id: str) -> User:
    row = db.get(User, user_id)
    if row is None:
        raise HTTPException(status_code=404, detail={
            "code": "user_not_found", "message": "no such user"})
    return row


@router.get("/users")
def list_users(request: Request, db: Session = Depends(get_db),
               _: User | None = Depends(require_admin)):
    """All registered users, newest sessions first, with live-state flags."""
    caller_hash = _caller_hash(request)
    users = db.query(User).order_by(User.created_at.asc()).all()
    payload = []
    for user in users:
        sessions = (db.query(UserSession)
                    .filter(UserSession.user_id == user.id)
                    .order_by(UserSession.created_at.desc())
                    .all())
        states = [session_state(s) for s in sessions]
        payload.append({
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "is_admin": is_admin_user(user),
            "is_active": user.is_active,
            "created_at": _iso(user.created_at),
            "last_login_at": _iso(user.last_login_at),
            "active_sessions": sum(1 for s in states if s == "live"),
            "total_sessions": len(sessions),
            "sessions": [_session_payload(s, caller_hash) for s in sessions],
        })
    return {
        "users": payload,
        "count": len(payload),
        "note": ("Sessions live until revoked or expired; revoking takes effect "
                 "on the revoked session's next request. Password hashes and "
                 "raw tokens are never returned."),
    }


@router.get("/users/{user_id}/sessions")
def user_sessions(user_id: str, request: Request, db: Session = Depends(get_db),
                  _: User | None = Depends(require_admin)):
    """Session history for one user (all states, newest first)."""
    _get_user_row(db, user_id)
    caller_hash = _caller_hash(request)
    rows = (db.query(UserSession)
            .filter(UserSession.user_id == user_id)
            .order_by(UserSession.created_at.desc())
            .all())
    return {"sessions": [_session_payload(r, caller_hash) for r in rows],
            "count": len(rows)}


@router.delete("/sessions/{session_id}")
def revoke_one_session(session_id: str, request: Request, db: Session = Depends(get_db),
                       admin: User | None = Depends(require_admin)):
    """Revoke a single session; the credential dies on its next request."""
    row = _get_session_row(db, session_id)
    actor = current_actor(request)
    already = row.revoked_at is not None
    if not already:
        row.revoked_at = utcnow()
        db.flush()
    audit(db, "admin.session_revoked", actor=actor,
          entity_type="user_session", entity_id=row.id,
          detail={"target_user_id": row.user_id,
                  "already_revoked": already,
                  "current_session": bool(_caller_hash(request)) and
                                     _caller_hash(request) == row.token_hash})
    db.commit()
    return {"revoked": not already, "session_id": row.id,
            "message": ("session already revoked" if already
                        else "session revoked — its token is rejected from "
                             "the next request onwards")}


@router.post("/users/{user_id}/revoke-sessions")
def revoke_all_sessions(user_id: str, request: Request, db: Session = Depends(get_db),
                        admin: User | None = Depends(require_admin)):
    """Revoke every live session belonging to a user at once."""
    _get_user_row(db, user_id)
    revoked = revoke_user_sessions(db, user_id)
    audit(db, "admin.all_sessions_revoked", actor=current_actor(request),
          entity_type="user", entity_id=user_id,
          detail={"revoked": revoked})
    db.commit()
    return {"revoked": revoked, "user_id": user_id,
            "message": f"{revoked} session(s) revoked"}
