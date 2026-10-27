"""User account authentication: sign-up, sign-in, sessions, ownership.

The domain suite (conftest) runs with TRACEX_USER_AUTH_ENABLED=false so
existing tests exercise trusted-local mode.  These tests flip the flag on
dynamically — the middleware and `auth_on()` read config at request time —
to exercise the real login flow: credential validation, HttpOnly-cookie
sessions (bearer headers still accepted for scripts), the enforcement
guard, login throttling and per-user ownership isolation.
"""

from __future__ import annotations

import hashlib

import pytest

from app.config import SESSION_COOKIE_NAME


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    """The throttle is in-process state; clear it so tests stay independent."""
    from app.services import accounts

    accounts._attempts.clear()
    yield
    accounts._attempts.clear()


@pytest.fixture()
def user_auth(monkeypatch):
    """Turn on session enforcement for one test, restoring the default after."""
    from app import config

    monkeypatch.setattr(config, "USER_AUTH_ENABLED", True)


@pytest.fixture()
def alice(client):
    """Sign in as Alice (idempotent: the DB is shared across tests)."""
    return _ensure_user(client, "Alice", "correct-horse-1", "Alice Liddell")


@pytest.fixture()
def bob(client):
    return _ensure_user(client, "bob", "bobs-secure-pw")


def _ensure_user(client, username: str, password: str,
                 display_name: str | None = None) -> str:
    """Signup on first use, login on later tests in the same session.

    Returns the raw session token — delivered only via the HttpOnly cookie,
    which the test client's jar stores automatically.
    """
    payload = {"username": username, "password": password}
    if display_name:
        payload["display_name"] = display_name
    resp = client.post("/api/auth/signup", json=payload)
    if resp.status_code == 409:  # created by an earlier test
        resp = client.post("/api/auth/login", json={
            "username": username, "password": password})
    assert resp.status_code in (200, 201), resp.text
    token = resp.cookies.get(SESSION_COOKIE_NAME)
    assert token, "session cookie missing from the auth response"
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Sign-up
# ---------------------------------------------------------------------------

def test_signup_returns_session_without_leaking_secrets(client, db):
    resp = client.post("/api/auth/signup", json={
        "username": "Carla", "password": "very-long-passphrase",
        "display_name": "Carla Q."})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    # the token exists only as an HttpOnly cookie — never in the body JS reads
    assert "token" not in body
    cookie_header = resp.headers.get("set-cookie", "").lower()
    assert SESSION_COOKIE_NAME.lower() in cookie_header
    assert "httponly" in cookie_header
    assert "samesite=lax" in cookie_header
    token = resp.cookies.get(SESSION_COOKIE_NAME)
    assert token
    assert body["user"]["username"] == "carla"  # normalised to lowercase
    assert body["user"]["display_name"] == "Carla Q."  # kept as given
    assert "password" not in str(body).replace("password_hash", "")

    from app.models import User, UserSession

    user = db.query(User).filter(User.username == "carla").one()
    # stored hash is PBKDF2, never the plaintext
    assert user.password_hash.startswith("pbkdf2_sha256$")
    assert "very-long-passphrase" not in user.password_hash
    # session stores only the SHA-256 of the token
    session = db.query(UserSession).filter(UserSession.user_id == user.id).one()
    assert session.token_hash == hashlib.sha256(
        token.encode()).hexdigest()
    assert token not in session.token_hash
    # the signing-in client address is recorded for the admin session list
    assert session.client_ip == "testclient"  # TestClient's default peer


def test_signup_rejects_duplicate_username(client, alice):
    resp = client.post("/api/auth/signup", json={
        "username": "ALICE", "password": "another-pass-9"})
    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "username_taken"


@pytest.mark.parametrize("username,password,code", [
    ("ab", "long-enough-pw", "invalid_username"),          # too short
    ("a b c", "long-enough-pw", "invalid_username"),       # illegal chars
    ("-leading", "long-enough-pw", "invalid_username"),    # bad boundary
    ("valid_user", "short", "weak_password"),              # password < 8
])
def test_signup_validation(client, username, password, code):
    resp = client.post("/api/auth/signup", json={
        "username": username, "password": password})
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["code"] == code


# ---------------------------------------------------------------------------
# Sign-in
# ---------------------------------------------------------------------------

def test_login_success_and_failure(client, alice, db):
    ok = client.post("/api/auth/login", json={
        "username": "alice", "password": "correct-horse-1"})
    assert ok.status_code == 200
    # no token in the JSON body; the credential is the HttpOnly cookie
    assert "token" not in ok.json()
    assert ok.cookies.get(SESSION_COOKIE_NAME)
    assert ok.json()["user"]["username"] == "alice"

    wrong = client.post("/api/auth/login", json={
        "username": "alice", "password": "wrong-password"})
    assert wrong.status_code == 401
    assert wrong.json()["detail"]["code"] == "invalid_credentials"

    unknown = client.post("/api/auth/login", json={
        "username": "ghost", "password": "whatever-here"})
    # identical status/code for unknown user vs wrong password: no enumeration
    assert unknown.status_code == 401
    assert unknown.json()["detail"]["code"] == "invalid_credentials"

    # failed login is audited, successful one too
    from app.models import AuditLog

    actions = [a.action for a in db.query(AuditLog).all()]
    assert "auth.login" in actions
    assert "auth.login_failed" in actions
    assert "auth.signup" in actions


def test_login_throttled_after_repeated_failures(client, alice):
    for _ in range(5):
        resp = client.post("/api/auth/login", json={
            "username": "alice", "password": "bad-password"})
        assert resp.status_code == 401
    blocked = client.post("/api/auth/login", json={
        "username": "alice", "password": "correct-horse-1"})
    assert blocked.status_code == 429
    assert blocked.json()["detail"]["code"] == "too_many_attempts"


# ---------------------------------------------------------------------------
# Session enforcement (middleware)
# ---------------------------------------------------------------------------

def test_public_auth_endpoints_work_without_token(client, user_auth):
    status = client.get("/api/auth/status")
    assert status.status_code == 200
    assert status.json()["user_auth_required"] is True
    assert status.json()["user"] is None
    # health stays public so the UI can probe the backend before login
    assert client.get("/api/health").status_code == 200


def test_guard_requires_token_when_auth_on(client, user_auth):
    resp = client.get("/api/investigations")
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "auth_required"

    fake = client.get("/api/investigations", headers=_auth("not-a-real-token"))
    assert fake.status_code == 401

    # signup then use the cookie-set session: request passes the guard
    signup = client.post("/api/auth/signup", json={
        "username": "dina", "password": "dinas-secret-1"})
    token = signup.cookies.get(SESSION_COOKIE_NAME)
    assert token
    allowed = client.get("/api/investigations", headers=_auth(token))
    assert allowed.status_code == 200

    # status now reports the signed-in user
    status = client.get("/api/auth/status", headers=_auth(token))
    assert status.json()["user"]["username"] == "dina"

    me = client.get("/api/auth/me", headers=_auth(token))
    assert me.status_code == 200
    assert me.json()["user"]["username"] == "dina"


def test_logout_revokes_session(client, user_auth, alice):
    assert client.get("/api/auth/me", headers=_auth(alice)).status_code == 200
    out = client.post("/api/auth/logout", headers=_auth(alice))
    assert out.status_code == 200
    assert out.json()["revoked"] is True
    # token is dead everywhere afterwards
    assert client.get("/api/auth/me", headers=_auth(alice)).status_code == 401
    assert client.get("/api/investigations",
                      headers=_auth(alice)).status_code == 401


def test_expired_session_rejected(client, user_auth, db, alice):
    """Backdate *Alice's* session (not an arbitrary row) and expect a 401."""
    from datetime import timedelta

    from app.models import UserSession, utcnow

    token_hash = hashlib.sha256(alice.encode()).hexdigest()
    row = (db.query(UserSession)
           .filter(UserSession.token_hash == token_hash).one())
    row.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    assert client.get("/api/investigations",
                      headers=_auth(alice)).status_code == 401


# ---------------------------------------------------------------------------
# Ownership isolation between users
# ---------------------------------------------------------------------------

def test_investigations_are_isolated_between_users(client, user_auth,
                                                    alice, bob):
    created = client.post(
        "/api/investigations",
        json={"name": "Alice case", "case_id": "CASE-ALICE-1"},
        headers=_auth(alice))
    assert created.status_code == 201, created.text
    case_id = created.json()["id"]
    assert created.json()["owner"] == "alice"  # username becomes the owner

    # Alice sees her case (plus any unowned ones)...
    alice_list = client.get("/api/investigations", headers=_auth(alice))
    assert case_id in [i["id"] for i in alice_list.json()["investigations"]]

    # ...Bob does not
    bob_list = client.get("/api/investigations", headers=_auth(bob))
    assert case_id not in [i["id"] for i in bob_list.json()["investigations"]]

    # Bob cannot read, mutate or import into Alice's case either
    assert client.get(f"/api/investigations/{case_id}",
                      headers=_auth(bob)).status_code in (403, 404)
    patch = client.patch(f"/api/investigations/{case_id}",
                         json={"name": "hijacked"}, headers=_auth(bob))
    assert patch.status_code == 403
    assert patch.json()["detail"]["code"] == "not_owner"

    # Alice (the owner) still can
    own = client.patch(f"/api/investigations/{case_id}",
                       json={"name": "Alice case renamed"},
                       headers=_auth(alice))
    assert own.status_code == 200


def test_actor_recorded_from_session_in_audit(client, user_auth, alice):
    client.post("/api/investigations",
                json={"name": "Audited", "case_id": "CASE-AUDIT-1"},
                headers=_auth(alice))
    inv = [i for i in client.get("/api/investigations",
                                 headers=_auth(alice)).json()["investigations"]
           if i["case_id"] == "CASE-AUDIT-1"][0]
    entries = client.get(f"/api/investigations/{inv['id']}/audit",
                         headers=_auth(alice)).json()["entries"]
    created = [e for e in entries if e["action"] == "investigation.created"]
    assert created and created[0]["actor"] == "alice"


# ---------------------------------------------------------------------------
# Trusted-local mode stays intact (flag off)
# ---------------------------------------------------------------------------

def test_domain_mode_unaffected_without_flag(client):
    # conftest keeps the flag off: no token needed, nothing401s
    assert client.get("/api/investigations").status_code == 200
    status = client.get("/api/auth/status").json()
    assert status["user_auth_required"] is False
    assert status["auth_mode"] == "trusted_local"
