"""API-key authentication and actor resolution.

When `TRACEX_AUTH_ENABLED=true`, every mutating request must carry an API key
(`Authorization: Bearer <token>` or `X-API-Key: <token>`); the key's registered
name becomes the audit actor and investigation owner.  Tokens are compared in
constant time and are never logged or echoed back.

When auth is disabled (the default for single-investigator local use), the
legacy `X-TraceX-Actor` header is honoured so existing behaviour is unchanged.
"""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

from .config import API_KEYS, AUTH_ENABLED, DEFAULT_ACTOR, SESSION_COOKIE_NAME


def auth_on() -> bool:
    """True when any server-side authentication mode is active.

    Read dynamically at call time so tests (and future config reloads) can
    toggle modes without reimporting the app.
    """
    from . import config

    return AUTH_ENABLED or config.USER_AUTH_ENABLED


def _extract_token(request: Request) -> str | None:
    """The session credential for this request: bearer header, API-key header
    or the HttpOnly session cookie — in that order, so scripts using explicit
    headers keep working and the browser's cookie is the fallback."""
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return token
    header_key = (request.headers.get("x-api-key") or "").strip()
    if header_key:
        return header_key
    # getattr like `state` above: simple test doubles need not model cookies
    cookies = getattr(request, "cookies", None) or {}
    cookie_key = (cookies.get(SESSION_COOKIE_NAME) or "").strip()
    return cookie_key or None


def _match_api_key(token: str) -> str | None:
    """Return the registered name for `token`, compared in constant time."""
    matched: str | None = None
    for name, registered in API_KEYS.items():
        if hmac.compare_digest(token.encode("utf-8"), registered.encode("utf-8")):
            matched = name  # keep iterating: constant-time across all entries
    return matched


def current_actor(request: Request) -> str:
    """FastAPI dependency resolving the acting identity for a request.

    * user session auth on -> the signed-in username (set by the auth
      middleware after validating the bearer token);
    * API-key auth on     -> requires a valid API key; the key name is the actor;
    * auth disabled       -> `X-TraceX-Actor` header or the configured default.
    """
    # `state` only exists on real Starlette requests (and is only populated
    # by the auth middleware); getattr keeps simple test doubles working.
    session_state = getattr(request, "state", None)
    session_user = getattr(session_state, "user", None)
    if session_user is not None:
        return session_user.username
    if AUTH_ENABLED:
        token = _extract_token(request)
        if not token:
            raise HTTPException(status_code=401, detail={
                "code": "auth_required",
                "message": "this TRACE-X instance requires an API key "
                           "(Authorization: Bearer <token> or X-API-Key)"})
        name = _match_api_key(token)
        if name is None:
            raise HTTPException(status_code=401, detail={
                "code": "invalid_api_key", "message": "the supplied API key is not recognised"})
        return name

    header_actor = (request.headers.get("x-tracex-actor") or "").strip()
    return header_actor[:128] or DEFAULT_ACTOR


def owner_or_open(actor: str) -> str | None:
    """Owner filter value for listings: the actor when auth is on, else None."""
    return actor if auth_on() else None
