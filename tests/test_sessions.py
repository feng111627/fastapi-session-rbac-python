"""Multi-device sessions, logout/revoke immediacy, restart recovery."""
from __future__ import annotations

import logging

from app.errors import Reason
from app.main import create_app
from tests.conftest import auth_header, login

log = logging.getLogger("test.sessions")


def test_logout_invalidates_immediately(client):
    pair = login(client, "alice", "alice-pass")
    assert client.post("/auth/logout",
                       json={"refresh_token": pair["refresh_token"]}).status_code == 204
    # refresh token dead
    resp = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.TOKEN_INVALID
    # access token dead too (session revoked)
    resp = client.get("/profile", headers=auth_header(pair["access_token"]))
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.TOKEN_REVOKED
    log.info("logout invalidated refresh and access immediately")


def test_multi_device_sessions_and_targeted_revoke(client):
    phone = login(client, "alice", "alice-pass", device="phone")
    laptop = login(client, "alice", "alice-pass", device="laptop")

    sessions = client.get("/auth/sessions", headers=auth_header(phone["access_token"]))
    assert sessions.status_code == 200
    devices = {s["device"]: s["session_id"] for s in sessions.json()}
    assert set(devices) == {"phone", "laptop"}

    # revoke only the laptop session
    assert client.post(f"/auth/sessions/{devices['laptop']}/revoke",
                       headers=auth_header(phone["access_token"])).status_code == 204
    # laptop is dead immediately
    resp = client.get("/profile", headers=auth_header(laptop["access_token"]))
    assert resp.json()["error"] == Reason.TOKEN_REVOKED
    resp = client.post("/auth/refresh", json={"refresh_token": laptop["refresh_token"]})
    assert resp.status_code == 401
    # phone still works
    assert client.get("/profile", headers=auth_header(phone["access_token"])).status_code == 200
    assert client.post("/auth/refresh",
                       json={"refresh_token": phone["refresh_token"]}).status_code == 200
    log.info("targeted revoke killed laptop session, phone unaffected")


def test_cannot_revoke_other_users_session(client):
    alice = login(client, "alice", "alice-pass")
    bob = login(client, "bob", "bob-pass")
    alice_sid = client.get("/auth/sessions", headers=auth_header(alice["access_token"])) \
        .json()[0]["session_id"]
    resp = client.post(f"/auth/sessions/{alice_sid}/revoke",
                       headers=auth_header(bob["access_token"]))
    assert resp.status_code == 404
    # alice's session untouched
    assert client.get("/profile", headers=auth_header(alice["access_token"])).status_code == 200
    log.info("cross-user session revoke refused with 404")


def test_sessions_and_revocation_survive_restart(settings):
    from fastapi.testclient import TestClient

    app1 = create_app(settings)
    c1 = TestClient(app1)
    keep = login(c1, "alice", "alice-pass", device="keep")
    drop = login(c1, "alice", "alice-pass", device="drop")
    drop_sid = [s for s in c1.get("/auth/sessions", headers=auth_header(keep["access_token"]))
                .json() if s["device"] == "drop"][0]["session_id"]
    c1.post(f"/auth/sessions/{drop_sid}/revoke", headers=auth_header(keep["access_token"]))
    app1.state.store.close()
    log.info("simulated restart: recreating app on the same db file")

    app2 = create_app(settings)
    c2 = TestClient(app2)
    # live session still usable after restart
    resp = c2.post("/auth/refresh", json={"refresh_token": keep["refresh_token"]})
    assert resp.status_code == 200
    assert c2.get("/profile", headers=auth_header(keep["access_token"])).status_code == 200
    # revoked session stays revoked
    resp = c2.get("/profile", headers=auth_header(drop["access_token"]))
    assert resp.json()["error"] == Reason.TOKEN_REVOKED
    resp = c2.post("/auth/refresh", json={"refresh_token": drop["refresh_token"]})
    assert resp.status_code == 401
    log.info("sessions and revocation state recovered after restart")
