"""User account endpoints: sign up, sign in, sign out, session introspection.

Credentials policy
  * Usernames are normalised to lowercase and must match a conservative
    pattern (see accounts service); passwords need >= 8 characters and are
    stored only as PBKDF2 hashes.
  * The session credential is returned only as an HttpOnly, SameSite=Lax
    cookie — page JavaScript can never read it, and it is never echoed in a
    response body.  The server keeps only the token's SHA-256 digest.
  * Login attempts are throttled per username+IP; failed and successful
    auth events are written to the audit trail (never with credentials).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from .. import config
from ..auth import _extract_token
from ..config import SESSION_COOKIE_NAME
from ..db import get_db
from ..models import User, utcnow
from ..schemas import LoginRequest, SignupRequest
from ..services.accounts import (
    AccountError,
    authenticate,
    clear_failed_logins,
    create_user,
    is_admin_user,
    issue_session,
    record_failed_login,
    revoke_session,
    resolve_session,
    throttle_retry_after,
)
from ..services.ingest import audit

router = APIRouter(prefix="/auth", tags=["auth"])

# Public: the UI must be able to learn whether login is required and to
# sign in / sign up before it holds any token.
PUBLIC_PATHS = {"/auth/status", "/auth/signup", "/auth/login"}


def bearer_token(request: Request) -> str | None:
    """Session credential: Authorization header or the HttpOnly cookie."""
    return _extract_token(request)


def _set_session_cookie(response: Response, request: Request, token: str) -> None:
    """Hand the session token to the browser as an unreadable cookie.

    HttpOnly keeps it out of page JavaScript; SameSite=Lax blocks cross-site
    transmission of the credential; Secure is added on HTTPS so plain-HTTP
    local development keeps working.
    """
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=config.SESSION_HOURS * 3600,
        path="/",
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _user_payload(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "is_admin": is_admin_user(user),
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def _account_http_error(exc: AccountError) -> HTTPException:
    status = 409 if exc.code == "username_taken" else 400
    return HTTPException(status_code=status, detail={"code": exc.code, "message": str(exc)})


@router.get("/status")
def auth_status(request: Request, db: Session = Depends(get_db)):
    """Tell the UI whether a sign-in is required and who is signed in (if any)."""
    token = bearer_token(request)
    user = resolve_session(db, token) if token else None
    required = config.USER_AUTH_ENABLED
    return {
        "user_auth_required": required,
        "user": _user_payload(user) if user else None,
        "auth_mode": "user_session" if required else "trusted_local",
        "note": (
            "Sign in to continue; your username becomes the audit actor and the "
            "owner of investigations you create."
            if required else
            "User auth is disabled on this instance (TRACEX_USER_AUTH_ENABLED=false). "
            "Do not expose it beyond localhost."
        ),
    }


@router.post("/signup", status_code=201)
def signup(body: SignupRequest, request: Request, response: Response,
           db: Session = Depends(get_db)):
    try:
        user = create_user(db, body.username, body.password, body.display_name)
    except AccountError as exc:
        db.rollback()
        raise _account_http_error(exc)
    token, session_row = issue_session(db, user, request.headers.get("user-agent"),
                                       _client_ip(request))
    audit(db, "auth.signup", actor=user.username,
          entity_type="user", entity_id=user.id,
          detail={"username": user.username})
    db.commit()
    _set_session_cookie(response, request, token)
    return {
        "expires_at": session_row.expires_at.isoformat(),
        "user": _user_payload(user),
        "message": f"Welcome, {user.display_name or user.username}. Your account is ready.",
    }


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response,
          db: Session = Depends(get_db)):
    ip = _client_ip(request)
    retry_after = throttle_retry_after(body.username, ip)
    if retry_after is not None:
        raise HTTPException(status_code=429, detail={
            "code": "too_many_attempts",
            "message": f"too many failed sign-in attempts; try again in {retry_after} s",
            "details": {"retry_after_seconds": retry_after}})

    user = authenticate(db, body.username, body.password)
    if user is None:
        record_failed_login(body.username, ip)
        audit(db, "auth.login_failed", actor=body.username.strip().lower()[:128] or "unknown",
              detail={"username": body.username.strip().lower()[:64], "client": ip})
        db.commit()
        raise HTTPException(status_code=401, detail={
            "code": "invalid_credentials",
            "message": "invalid username or password"})

    clear_failed_logins(body.username, ip)
    token, session_row = issue_session(db, user, request.headers.get("user-agent"), ip)
    audit(db, "auth.login", actor=user.username,
          entity_type="user", entity_id=user.id,
          detail={"username": user.username, "client": ip})
    db.commit()
    _set_session_cookie(response, request, token)
    return {
        "expires_at": session_row.expires_at.isoformat(),
        "user": _user_payload(user),
    }


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Revoke the presented session token; idempotent for unknown tokens."""
    token = bearer_token(request)
    user = resolve_session(db, token) if token else None
    revoked = revoke_session(db, token) if token else False
    if user is not None:
        audit(db, "auth.logout", actor=user.username,
              entity_type="user", entity_id=user.id,
              detail={"username": user.username})
    db.commit()
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"revoked": revoked, "message": "signed out"}


@router.get("/me")
def me(request: Request, db: Session = Depends(get_db)):
    """The signed-in user for this request; 401 without a live session."""
    token = bearer_token(request)
    user = resolve_session(db, token) if token else None
    if user is None:
        raise HTTPException(status_code=401, detail={
            "code": "auth_required", "message": "sign in to continue"})
    return {"user": _user_payload(user), "authenticated_at": utcnow().isoformat()}
