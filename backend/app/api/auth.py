"""Authentication introspection endpoint.

`GET /api/auth/verify` tells the caller which identity the server resolved for
the request — the exact value that will be recorded as the audit actor and used
as the investigation owner.  It never echoes tokens back.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..auth import current_actor
from ..config import AUTH_ENABLED

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/verify")
def verify_identity(request: Request, actor: str = Depends(current_actor)):
    """Return the acting identity for this request.

    When auth is enabled this 401s without a valid API key (the dependency
    enforces it); when disabled it reports the header-derived or default actor.
    """
    from .. import config

    session_user = getattr(request.state, "user", None)
    has_key = bool(
        (request.headers.get("authorization") or "").lower().startswith("bearer ")
        or (request.headers.get("x-api-key") or "").strip()
    )
    if session_user is not None:
        auth_mode = "user_session"
        note = ("Signed in as a user account. The username is recorded on every "
                "audit entry and becomes the owner of newly created investigations.")
    elif AUTH_ENABLED:
        auth_mode = "api_key"
        note = ("The actor is recorded on every audit entry and becomes the owner of "
                "newly created investigations. Tokens are never stored or echoed back.")
    elif config.USER_AUTH_ENABLED:
        # Guard rejected anything without a session, so reaching here means the
        # request was exempt (health/status) or auth was just toggled.
        auth_mode = "user_session_required"
        note = "This instance requires a user session; sign in via /api/auth/login."
    else:
        auth_mode = "trusted_local"
        note = ("Auth is disabled: the X-TraceX-Actor header (or the configured "
                "default) sets the actor. Do not expose this instance beyond localhost.")
    return {
        "authenticated": AUTH_ENABLED or config.USER_AUTH_ENABLED,
        "actor": actor,
        "auth_mode": auth_mode,
        "key_presented": has_key if AUTH_ENABLED and session_user is None else None,
        "note": note,
    }
