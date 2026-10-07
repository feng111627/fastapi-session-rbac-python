"""Session lifecycle: idle timeout, absolute lifetime cap, bulk revoke
("log out other devices"), terminal-session cleanup, restart recovery and
pre-upgrade database migration."""
from __future__ import annotations

import logging
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.errors import AuthError, Reason
from app.main import create_app
from app.tokens import hash_refresh_token, new_refresh_token
from tests.conftest import auth_header, login

log = logging.getLogger("test.lifecycle")


class Clock:
    """Controllable clock: starts at real time, advanced manually."""

    def __init__(self) -> None:
        self.t = time.time()

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def make_lifecycle(tmp_path, **overrides):
    """App with short lifecycle windows and a controllable clock."""
    clock = Clock()
    kwargs = dict(
        db_path=str(tmp_path / "auth.db"),
        session_idle_timeout_seconds=100,
        session_max_lifetime_seconds=1000,
        terminated_session_retention_seconds=50,
        # keep JWT/refresh-token expiry out of the way of the fake clock
        access_token_ttl_seconds=100000,
        refresh_token_ttl_seconds=100000,
    )
    kwargs.update(overrides)
    settings = Settings(**kwargs)
    app = create_app(settings, now_fn=clock)
    return TestClient(app), app, clock, settings


@pytest.fixture()
def lifecycle(tmp_path):
    return make_lifecycle(tmp_path)


def _sid_of(auth, username: str, device: str) -> str:
    return next(s.session_id for s in auth.list_sessions(username) if s.device == device)


# -- idle timeout ------------------------------------------------------------

def test_idle_timeout_invalidates_access_and_refresh(lifecycle):
    client, _, clock, _ = lifecycle
    pair = login(client, "alice", "alice-pass", device="phone")
    clock.advance(150)  # idle window is 100s, no activity since login

    resp = client.get("/profile", headers=auth_header(pair["access_token"]))
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.SESSION_IDLE_EXPIRED
    resp = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.SESSION_IDLE_EXPIRED
    log.info("idle session rejected with session_idle_expired on access and refresh, "
             "distinct from revoked/expired/invalid")


def test_refresh_counts_as_activity_and_slides_idle_window(lifecycle):
    client, _, clock, _ = lifecycle
    pair = login(client, "alice", "alice-pass")
    for _ in range(3):
        clock.advance(80)  # each step stays inside the 100s idle window
        resp = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        assert resp.status_code == 200, resp.text
        pair = resp.json()
    log.info("session survived %ds of idle<window activity via refreshes", 3 * 80)
    # session list reflects the recent activity
    sessions = client.get("/auth/sessions", headers=auth_header(pair["access_token"])).json()
    assert sessions[0]["status"] == "active"
    assert sessions[0]["last_active_at"] > sessions[0]["created_at"]
    # stop being active: the idle window finally lapses
    clock.advance(150)
    resp = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.json()["error"] == Reason.SESSION_IDLE_EXPIRED
    log.info("idle window lapsed once activity stopped; session invalidated")


def test_absolute_lifetime_caps_continuously_active_session(tmp_path):
    client, _, clock, _ = make_lifecycle(tmp_path, session_max_lifetime_seconds=300)
    pair = login(client, "alice", "alice-pass")
    # stay active well within the idle window the whole time
    for _ in range(3):
        clock.advance(80)
        resp = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        assert resp.status_code == 200, resp.text
        pair = resp.json()
    clock.advance(80)  # t=320 > 300s absolute cap, idle only 80s < 100s
    resp = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.TOKEN_EXPIRED
    resp = client.get("/profile", headers=auth_header(pair["access_token"]))
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.TOKEN_EXPIRED
    log.info("continuously active session still died at the absolute lifetime cap "
             "with token_expired (not idle)")


# -- log out other devices -----------------------------------------------------

def test_revoke_others_kills_other_devices_immediately(lifecycle):
    client, _, _, _ = lifecycle
    phone = login(client, "alice", "alice-pass", device="phone")
    laptop = login(client, "alice", "alice-pass", device="laptop")
    tablet = login(client, "alice", "alice-pass", device="tablet")

    resp = client.post("/auth/sessions/revoke-others",
                       headers=auth_header(phone["access_token"]))
    assert resp.status_code == 200
    assert resp.json()["revoked"] == 2

    for dead in (laptop, tablet):
        resp = client.get("/profile", headers=auth_header(dead["access_token"]))
        assert resp.json()["error"] == Reason.TOKEN_REVOKED
        resp = client.post("/auth/refresh", json={"refresh_token": dead["refresh_token"]})
        assert resp.status_code == 401  # credentials deleted, same as logout
    # current device untouched
    assert client.get("/profile", headers=auth_header(phone["access_token"])).status_code == 200
    # list shows the revoked status and reason
    sessions = client.get("/auth/sessions", headers=auth_header(phone["access_token"])).json()
    by_device = {s["device"]: s for s in sessions}
    assert by_device["phone"]["status"] == "active"
    assert by_device["laptop"]["status"] == "revoked"
    assert by_device["laptop"]["revoke_reason"] == "logout_others"
    log.info("revoke-others killed laptop+tablet immediately, phone spared")


def test_revoke_others_include_current_kills_everything(lifecycle):
    client, _, _, _ = lifecycle
    phone = login(client, "alice", "alice-pass", device="phone")
    laptop = login(client, "alice", "alice-pass", device="laptop")
    resp = client.post("/auth/sessions/revoke-others?include_current=true",
                       headers=auth_header(phone["access_token"]))
    assert resp.json()["revoked"] == 2
    for dead in (phone, laptop):
        resp = client.get("/profile", headers=auth_header(dead["access_token"]))
        assert resp.json()["error"] == Reason.TOKEN_REVOKED
    log.info("include_current=true revoked every session of the account")


def test_revoke_others_concurrent_with_refresh_is_deterministic(app):
    """A session refreshing exactly while 'log out other devices' runs must
    end up with no usable credential, and the current device must survive."""
    client = TestClient(app)
    auth = app.state.auth
    current = auth.login("alice", "alice-pass", "current")
    other = auth.login("alice", "alice-pass", "other")
    current_sid = _sid_of(auth, "alice", "current")

    minted: list[str] = [other.refresh_token]

    def refresh_loop() -> None:
        token = other.refresh_token
        for _ in range(20):
            try:
                pair = auth.refresh(token)
            except AuthError:
                return
            token = pair.refresh_token
            minted.append(token)

    with ThreadPoolExecutor(max_workers=2) as pool:
        refresher = pool.submit(refresh_loop)
        revoker = pool.submit(auth.revoke_other_sessions, "alice", current_sid)
        refresher.result()
        revoked = revoker.result()
    assert revoked == 1
    # every credential the other device ever held is now dead
    for token in minted:
        with pytest.raises(AuthError) as err:
            auth.refresh(token)
        assert err.value.reason in (Reason.TOKEN_INVALID, Reason.SESSION_REVOKED)
    # the current device is fully usable
    assert auth.refresh(current.refresh_token)
    log.info("concurrent refresh vs revoke-others: %d minted tokens all dead, "
             "current device spared", len(minted))


# -- session list status & cleanup --------------------------------------------

def test_session_list_shows_lifecycle_status(tmp_path):
    client, app, clock, _ = make_lifecycle(
        tmp_path, terminated_session_retention_seconds=100000)
    auth = app.state.auth
    keep = login(client, "alice", "alice-pass", device="keep")
    login(client, "alice", "alice-pass", device="idle")
    revoked = login(client, "alice", "alice-pass", device="revoked")
    login(client, "alice", "alice-pass", device="expired")

    auth.revoke_session("alice", _sid_of(auth, "alice", "revoked"))
    store = app.state.store
    store._conn.execute("UPDATE sessions SET expires_at=? WHERE device='expired'",
                        (clock.t + 10,))
    store._conn.commit()

    clock.advance(90)
    keep = client.post("/auth/refresh", json={"refresh_token": keep["refresh_token"]}).json()
    clock.advance(70)  # t=160: idle lapsed at 100, expired lapsed at 10

    sessions = {s["device"]: s for s in
                client.get("/auth/sessions", headers=auth_header(keep["access_token"])).json()}
    assert sessions["keep"]["status"] == "active"
    assert sessions["idle"]["status"] == "idle_expired"
    assert sessions["revoked"]["status"] == "revoked"
    assert sessions["revoked"]["revoke_reason"] == "revoked_by_user"
    assert sessions["expired"]["status"] == "expired"
    for s in sessions.values():
        assert s["last_active_at"] > 0
    log.info("session list shows per-device status: %s",
             {d: s["status"] for d, s in sessions.items()})


def test_cleanup_purges_terminal_sessions_but_keeps_active(lifecycle):
    client, app, clock, _ = lifecycle
    auth = app.state.auth
    keep = login(client, "alice", "alice-pass", device="keep")
    idle = login(client, "alice", "alice-pass", device="idle")
    revoked = login(client, "alice", "alice-pass", device="revoked")
    expired = login(client, "alice", "alice-pass", device="expired")

    # revoke one now; backdate another past its absolute expiry
    auth.revoke_session("alice", _sid_of(auth, "alice", "revoked"))
    store = app.state.store
    store._conn.execute("UPDATE sessions SET expires_at=? WHERE device='expired'",
                        (clock.t + 10,))
    store._conn.commit()

    # keep the "keep" session busy so it stays active; let "idle" go stale
    clock.advance(90)
    keep = client.post("/auth/refresh", json={"refresh_token": keep["refresh_token"]}).json()
    clock.advance(70)  # t=160: idle(100)+retention(50) < 160 -> purgeable

    purged = auth.cleanup_expired()
    assert purged == 3
    remaining = [s.device for s in auth.list_sessions("alice")]
    assert remaining == ["keep"]
    # purged sessions' credentials are gone for good
    for dead in (idle, revoked, expired):
        with pytest.raises(AuthError) as err:
            auth.refresh(dead["refresh_token"])
        assert err.value.reason == Reason.TOKEN_INVALID
    # the active session that was refreshed mid-window was NOT purged
    assert client.post("/auth/refresh",
                       json={"refresh_token": keep["refresh_token"]}).status_code == 200
    assert client.get("/profile", headers=auth_header(keep["access_token"])).status_code == 200
    log.info("cleanup purged 3 terminal sessions, recently refreshed session intact")


# -- restart & upgrade ----------------------------------------------------------

def test_lifecycle_state_survives_restart(tmp_path):
    client, app1, clock, settings = make_lifecycle(tmp_path)
    pair = login(client, "alice", "alice-pass")
    clock.advance(50)
    pair = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]}).json()
    app1.state.store.close()
    log.info("simulated restart at t=%.0f (last activity t=50)", clock.t)

    app2 = create_app(settings, now_fn=clock)
    c2 = TestClient(app2)
    clock.advance(70)  # t=120: 70s since last activity < 100s idle window
    resp = c2.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.status_code == 200, "last_active_at must survive the restart"
    pair = resp.json()
    sessions = c2.get("/auth/sessions", headers=auth_header(pair["access_token"])).json()
    assert sessions[0]["status"] == "active"
    clock.advance(150)  # now idle for good
    resp = c2.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.json()["error"] == Reason.SESSION_IDLE_EXPIRED
    log.info("idle/activity state recovered after restart; idle expiry still enforced")


def test_pre_upgrade_database_migrates_and_keeps_sessions(tmp_path):
    """A database written before the lifecycle feature (no last_active_at
    column) must migrate cleanly and its sessions must stay usable."""
    db = str(tmp_path / "auth.db")
    conn = sqlite3.connect(db)
    conn.executescript("""
    CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                        roles TEXT NOT NULL);
    CREATE TABLE sessions (session_id TEXT PRIMARY KEY, username TEXT NOT NULL,
                           device TEXT NOT NULL, created_at REAL NOT NULL,
                           expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
                           revoke_reason TEXT);
    CREATE TABLE refresh_tokens (token_hash TEXT PRIMARY KEY, session_id TEXT NOT NULL,
                                 expires_at REAL NOT NULL,
                                 rotated INTEGER NOT NULL DEFAULT 0,
                                 created_at REAL NOT NULL);
    CREATE TABLE rate_limits (key TEXT PRIMARY KEY, fail_count INTEGER NOT NULL DEFAULT 0,
                              locked_until REAL NOT NULL DEFAULT 0);
    """)
    now = time.time()
    old_token = new_refresh_token()
    conn.execute("INSERT INTO sessions VALUES(?,?,?,?,?,0,NULL)",
                 ("old-session", "alice", "legacy-device", now - 3600, now + 100000))
    conn.execute("INSERT INTO refresh_tokens VALUES(?,?,?,0,?)",
                 (hash_refresh_token(old_token), "old-session", now + 100000, now - 3600))
    conn.commit()
    conn.close()
    log.info("created pre-upgrade database without last_active_at column")

    app = create_app(Settings(db_path=db, access_token_ttl_seconds=100000))
    client = TestClient(app)
    # the pre-upgrade session still refreshes (migration stamped its activity)
    resp = client.post("/auth/refresh", json={"refresh_token": old_token})
    assert resp.status_code == 200, resp.text
    pair = resp.json()
    assert client.get("/profile", headers=auth_header(pair["access_token"])).status_code == 200
    sessions = client.get("/auth/sessions", headers=auth_header(pair["access_token"])).json()
    legacy = next(s for s in sessions if s["device"] == "legacy-device")
    assert legacy["status"] == "active"
    assert legacy["last_active_at"] >= now
    log.info("pre-upgrade session migrated: usable, last_active_at stamped, status active")
