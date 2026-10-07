"""Session lifecycle: idle timeout, sliding activity, absolute lifetime cap,
status visibility, and dead-session cleanup.
"""
from __future__ import annotations

import logging
import time

from fastapi.testclient import TestClient

from app.errors import Reason
from app.storage import SessionState
from app.tokens import hash_refresh_token
from tests.conftest import auth_header, login

log = logging.getLogger("test.lifecycle")


def _backdate_activity(app, refresh_token: str, seconds_ago: float) -> str:
    store = app.state.store
    h = hash_refresh_token(refresh_token)
    with store._lock, store._conn:
        row = store._conn.execute(
            "SELECT session_id FROM refresh_tokens WHERE token_hash=?", (h,),
        ).fetchone()
        assert row is not None, "refresh token must still exist"
        sid = row[0]
        store._conn.execute(
            "UPDATE sessions SET last_active_at=? WHERE session_id=?",
            (time.time() - seconds_ago, sid),
        )
    return sid


def _backdate_absolute(app, session_id: str, created_seconds_ago: float) -> None:
    """Move created_at into the past and put the absolute deadline in the past."""
    store = app.state.store
    now = time.time()
    with store._lock, store._conn:
        store._conn.execute(
            "UPDATE sessions SET created_at=?, expires_at=? WHERE session_id=?",
            (now - created_seconds_ago, now - 1, session_id),
        )


# --------------------------------------------------------------------------- #
# idle timeout
# --------------------------------------------------------------------------- #
def test_idle_session_rejected_for_access_and_refresh_with_distinct_reason(app):
    settings = app.state.settings
    settings.session_idle_timeout_seconds = 60
    c = TestClient(app)
    pair = login(c, "alice", "alice-pass", device="phone")

    _backdate_activity(app, pair["refresh_token"], 61)

    resp = c.get("/profile", headers=auth_header(pair["access_token"]))
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.SESSION_IDLE
    log.info("idle access rejected with session_idle")

    # natural death keeps the token row, so refresh still reports the reason
    resp = c.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.SESSION_IDLE
    log.info("idle refresh rejected with session_idle")

    rec = app.state.store.list_sessions("alice")[0]
    assert rec.state is SessionState.IDLE


def test_active_use_slides_the_idle_window(app):
    settings = app.state.settings
    settings.session_idle_timeout_seconds = 60

    c = TestClient(app)
    pair = login(c, "alice", "alice-pass", device="phone")
    sid = _backdate_activity(app, pair["refresh_token"], 55)  # not idle yet

    # an authenticated request counts as activity and pushes the window out
    assert c.get("/profile", headers=auth_header(pair["access_token"])).status_code == 200
    rec = app.state.store.get_session(sid)
    assert time.time() - rec.last_active_at < 1
    log.info("access activity refreshed last_active_at")


def test_successful_refresh_slides_idle_window(app):
    settings = app.state.settings
    settings.session_idle_timeout_seconds = 60

    c = TestClient(app)
    pair = login(c, "alice", "alice-pass", device="phone")
    sid = _backdate_activity(app, pair["refresh_token"], 55)

    resp = c.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.status_code == 200
    rec = app.state.store.get_session(sid)
    assert time.time() - rec.last_active_at < 1
    log.info("successful refresh counted as activity and extended the idle window")


def test_idle_just_inside_boundary_still_alive(app):
    settings = app.state.settings
    settings.session_idle_timeout_seconds = 60

    c = TestClient(app)
    pair = login(c, "alice", "alice-pass")
    _backdate_activity(app, pair["refresh_token"], 59)
    assert c.get("/profile", headers=auth_header(pair["access_token"])).status_code == 200
    log.info("activity within the idle boundary keeps the session alive")


# --------------------------------------------------------------------------- #
# absolute lifetime cap
# --------------------------------------------------------------------------- #
def test_session_dies_at_absolute_cap_even_when_continuously_active(app):
    settings = app.state.settings
    settings.session_idle_timeout_seconds = 3600  # idle never fires here
    settings.session_max_lifetime_seconds = 1000

    c = TestClient(app)
    pair = login(c, "alice", "alice-pass", device="kiosk")
    sid = app.state.auth.list_sessions("alice")[0].session_id
    # keep using it right up to the wall: last_active_at is "now", so idle is
    # not the cause; only the absolute cap has elapsed
    _backdate_absolute(app, sid, 1000)
    _backdate_activity(app, pair["refresh_token"], 0)

    resp = c.get("/profile", headers=auth_header(pair["access_token"]))
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.SESSION_EXPIRED
    log.info("continuously active session still dies at the absolute cap (access)")

    resp = c.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.SESSION_EXPIRED
    log.info("continuously active session cannot refresh past the absolute cap")
    assert app.state.store.get_session(sid).state is SessionState.EXPIRED


def test_refresh_cannot_extend_past_absolute_cap(app):
    """The rotating refresh token never outlives the session's cap."""
    settings = app.state.settings
    settings.session_max_lifetime_seconds = 100
    settings.refresh_token_ttl_seconds = 100000

    c = TestClient(app)
    pair = login(c, "alice", "alice-pass")
    h = hash_refresh_token(pair["refresh_token"])
    row = app.state.store._conn.execute(
        "SELECT expires_at FROM refresh_tokens WHERE token_hash=?", (h,),
    ).fetchone()
    session = app.state.auth.list_sessions("alice")[0]
    assert row[0] <= session.expires_at + 1e-6
    log.info("issued refresh token is capped at the session absolute deadline")


# --------------------------------------------------------------------------- #
# status listing + cleanup
# --------------------------------------------------------------------------- #
def test_session_list_shows_last_active_and_status(app):
    settings = app.state.settings
    settings.session_idle_timeout_seconds = 60

    c = TestClient(app)
    pair = login(c, "alice", "alice-pass", device="phone")
    body = c.get("/auth/sessions", headers=auth_header(pair["access_token"])).json()
    assert len(body) == 1
    item = body[0]
    assert item["status"] == SessionState.ACTIVE.value
    assert "last_active_at" in item and item["last_active_at"] >= item["created_at"]
    log.info("session list exposes status and last_active_at")


def test_dead_sessions_show_terminal_status_until_retention_then_purged(app):
    settings = app.state.settings
    settings.dead_session_retain_seconds = 30

    c = TestClient(app)
    login(c, "alice", "alice-pass", device="phone")
    observer = login(c, "alice", "alice-pass", device="laptop")
    sid = next(
        s.session_id for s in app.state.auth.list_sessions("alice")
        if s.device == "phone"
    )
    app.state.store.revoke_session(sid, "revoked_by_user")

    body = c.get("/auth/sessions", headers=auth_header(observer["access_token"])).json()
    # list call performs maintenance but retention has not elapsed: still shown
    statuses = {s["device"]: s["status"] for s in body}
    assert statuses["phone"] == "revoked"
    log.info("dead session remains visible with terminal status within retention")

    # age the death beyond the retention window and run maintenance via listing
    with app.state.store._lock, app.state.store._conn as conn:
        conn.execute(
            "UPDATE sessions SET revoked_at=? WHERE session_id=?",
            (time.time() - 31, sid),
        )
    # pair is dead; trigger maintenance directly and confirm physical removal
    app.state.auth.run_session_maintenance()
    assert app.state.store.get_session(sid) is None
    assert app.state.store._conn.execute(
        "SELECT count(*) FROM refresh_tokens WHERE session_id=?", (sid,),
    ).fetchone()[0] == 0
    log.info("dead session and its credentials physically purged after retention")


def test_cleanup_never_deletes_in_use_sessions(app):
    settings = app.state.settings
    settings.dead_session_retain_seconds = 0

    c = TestClient(app)
    pair = login(c, "alice", "alice-pass", device="phone")
    sid = app.state.auth.list_sessions("alice")[0].session_id
    app.state.auth.run_session_maintenance()
    rec = app.state.store.get_session(sid)
    assert rec is not None and not rec.revoked
    assert c.get("/profile", headers=auth_header(pair["access_token"])).status_code == 200
    log.info("purge with zero retention does not touch an active session")


def test_cleanup_does_not_delete_a_session_just_refreshed(app):
    """A session that crossed idle must be dead; a just-refreshed (active)
    session must never be purged even if it is old and retention is zero."""
    settings = app.state.settings
    settings.session_idle_timeout_seconds = 3600
    settings.dead_session_retain_seconds = 0

    c = TestClient(app)
    pair = login(c, "alice", "alice-pass")
    sid = app.state.auth.list_sessions("alice")[0].session_id
    # old creation time, but absolute deadline still in the future + fresh use
    with app.state.store._lock, app.state.store._conn as conn:
        conn.execute(
            "UPDATE sessions SET created_at=?, expires_at=? WHERE session_id=?",
            (time.time() - 10_000, time.time() + 10_000, sid),
        )
    assert c.post("/auth/refresh",
                  json={"refresh_token": pair["refresh_token"]}).status_code == 200
    app.state.auth.run_session_maintenance()
    assert app.state.store.get_session(sid) is not None
    log.info("recently refreshed active session survives a concurrent purge")
