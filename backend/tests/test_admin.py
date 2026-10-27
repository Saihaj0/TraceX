"""Admin section: registered-user directory and session revocation.

Like test_accounts, these tests flip TRACEX_USER_AUTH_ENABLED on per-test and
grant admin through TRACEX_ADMIN_USERS membership (checked at request time).
Sessions travel as HttpOnly cookies; raw tokens captured from the cookie are
also replayed as bearer headers so a test can hold several sessions at once.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    """The throttle is in-process state; clear it so tests stay independent."""
    from app.services import accounts

    accounts._attempts.clear()
    yield
    accounts._attempts.clear()


@pytest.fixture()
def user_auth(monkeypatch):
    from app import config

    monkeypatch.setattr(config, "USER_AUTH_ENABLED", True)


@pytest.fixture()
def admin_user(monkeypatch, client):
    """An account that is admin via TRACEX_ADMIN_USERS membership."""
    from app import config

    monkeypatch.setattr(config, "ADMIN_USERS", {"registrar"})
    return _login(client, "registrar", "registrar-pw-1")


def _login(client, username: str, password: str) -> str:
    """Sign the user up (or in when the account exists) via the cookie flow."""
    from app.config import SESSION_COOKIE_NAME

    resp = client.post("/api/auth/signup",
                       json={"username": username, "password": password})
    if resp.status_code == 409:
        resp = client.post("/api/auth/login",
                           json={"username": username, "password": password})
    assert resp.status_code in (200, 201), resp.text
    token = resp.cookies.get(SESSION_COOKIE_NAME)
    assert token, "session cookie missing from the auth response"
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Access control & directory listing
# ---------------------------------------------------------------------------

def test_directory_requires_admin(client, user_auth, admin_user):
    intruder_token = _login(client, "intruder", "intruder-pw-99")

    # a signed-in non-admin is refused with a typed error
    denied = client.get("/api/admin/users", headers=_auth(intruder_token))
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "not_admin"

    # no credential at all: the guard rejects before routing
    client.cookies.clear()
    assert client.get("/api/admin/users").status_code == 401

    # the admin sees every account, newest session states included
    listing = client.get("/api/admin/users", headers=_auth(admin_user))
    assert listing.status_code == 200
    users = listing.json()["users"]
    names = {u["username"] for u in users}
    assert {"registrar", "intruder"} <= names
    intruder_row = [u for u in users if u["username"] == "intruder"][0]
    assert intruder_row["is_admin"] is False
    assert intruder_row["active_sessions"] >= 1
    assert intruder_row["sessions"], "sessions are listed inline per user"
    # each session row carries the device (user agent) and the client address
    for session in intruder_row["sessions"]:
        assert "client_ip" in session
    assert intruder_row["sessions"][0]["client_ip"] == "testclient"
    # never any credential material in the payload
    assert "password_hash" not in listing.text
    assert "token_hash" not in listing.text


def test_first_registered_account_becomes_admin(client, db):
    """Bootstrap rule: whoever is created first administers the instance."""
    from app.models import User

    if db.query(User).count() == 0:
        _login(client, "pioneer", "pioneer-pw-1")
    first = db.query(User).order_by(User.created_at.asc()).first()
    assert first is not None
    assert first.is_admin is True


# ---------------------------------------------------------------------------
# Session revocation
# ---------------------------------------------------------------------------

def test_admin_revokes_a_single_session(client, user_auth, admin_user, db):
    from app.config import SESSION_COOKIE_NAME

    # a second sign-in for the same account ("another device")
    second = client.post("/api/auth/login", json={
        "username": "registrar", "password": "registrar-pw-1"})
    assert second.status_code == 200
    second_token = second.cookies.get(SESSION_COOKIE_NAME)
    assert second_token and second_token != admin_user

    listing = client.get("/api/admin/users",
                         headers=_auth(admin_user)).json()
    me_row = [u for u in listing["users"] if u["username"] == "registrar"][0]
    live = [s for s in me_row["sessions"] if s["status"] == "live"]
    assert len(live) >= 2
    # the presented credential is flagged as the caller's own session
    current = [s for s in live if s["is_current"]]
    assert len(current) == 1
    # the newest other session is the "second device" just opened
    target = sorted([s for s in live if not s["is_current"]],
                    key=lambda s: s["created_at"] or "", reverse=True)[0]

    revoked = client.delete(f"/api/admin/sessions/{target['id']}",
                            headers=_auth(admin_user))
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True

    # the revoked token dies on its next request; the other session survives
    assert client.get("/api/auth/me",
                      headers=_auth(second_token)).status_code == 401
    assert client.get("/api/auth/me",
                      headers=_auth(admin_user)).status_code == 200

    # revoking the same session again is idempotent and reports it
    again = client.delete(f"/api/admin/sessions/{target['id']}",
                          headers=_auth(admin_user))
    assert again.status_code == 200
    assert again.json()["revoked"] is False

    # both revocations are in the audit trail
    from app.models import AuditLog

    actions = [a.action for a in db.query(AuditLog).all()]
    assert actions.count("admin.session_revoked") >= 2


def test_admin_revokes_all_sessions_of_a_user(client, user_auth, admin_user, db):
    from app.config import SESSION_COOKIE_NAME

    second = client.post("/api/auth/login", json={
        "username": "registrar", "password": "registrar-pw-1"})
    second_token = second.cookies.get(SESSION_COOKIE_NAME)
    assert second_token

    listing = client.get("/api/admin/users",
                         headers=_auth(admin_user)).json()
    me_row = [u for u in listing["users"] if u["username"] == "registrar"][0]
    live_before = me_row["active_sessions"]
    assert live_before >= 2

    result = client.post(f"/api/admin/users/{me_row['id']}/revoke-sessions",
                         headers=_auth(admin_user))
    assert result.status_code == 200
    assert result.json()["revoked"] >= 2

    # every session of the user is dead — including the caller's own
    assert client.get("/api/auth/me",
                      headers=_auth(admin_user)).status_code == 401
    assert client.get("/api/auth/me",
                      headers=_auth(second_token)).status_code == 401

    after = client.get("/api/admin/users", headers=_auth(second_token))
    assert after.status_code == 401  # and the directory is closed to them too


def test_admin_unknown_ids_are_404(client, user_auth, admin_user):
    assert client.delete("/api/admin/sessions/does-not-exist",
                         headers=_auth(admin_user)).status_code == 404
    assert client.post("/api/admin/users/does-not-exist/revoke-sessions",
                       headers=_auth(admin_user)).status_code == 404


# ---------------------------------------------------------------------------
# Trusted-local mode (flag off): the local caller is the operator
# ---------------------------------------------------------------------------

def test_admin_endpoints_work_in_trusted_local_mode(client):
    resp = client.get("/api/admin/users")
    assert resp.status_code == 200
    assert isinstance(resp.json()["users"], list)
