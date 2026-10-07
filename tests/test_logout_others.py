"""Logout other devices: immediate effect, current-device protection, and
deterministic outcome when a refresh races the bulk revocation.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.errors import AuthError, Reason
from tests.conftest import auth_header, login

log = logging.getLogger("test.logout_others")


def _sid_by_device(client, token, device):
    sessions = client.get("/auth/sessions", headers=auth_header(token)).json()
    return next(s["session_id"] for s in sessions if s["device"] == device)


def test_logout_others_kills_all_other_devices_immediately(client):
    phone = login(client, "alice", "alice-pass", device="phone")
    laptop = login(client, "alice", "alice-pass", device="laptop")
    tablet = login(client, "alice", "alice-pass", device="tablet")

    resp = client.post(
        "/auth/sessions/logout-others", json={"all_devices": False},
        headers=auth_header(phone["access_token"]),
    )
    assert resp.status_code == 200
    assert resp.json() == {"revoked": 2}
    log.info("logout-others revoked the other two devices")

    for other in (laptop, tablet):
        acc = client.get("/profile", headers=auth_header(other["access_token"]))
        assert acc.status_code == 401
        assert acc.json()["error"] == Reason.TOKEN_REVOKED
        ref = client.post("/auth/refresh", json={"refresh_token": other["refresh_token"]})
        assert ref.status_code == 401
    log.info("revoked devices rejected on both access and refresh immediately")

    # current device untouched
    assert client.get("/profile",
                      headers=auth_header(phone["access_token"])).status_code == 200
    assert client.post("/auth/refresh",
                       json={"refresh_token": phone["refresh_token"]}).status_code == 200
    log.info("current device keeps working after logout-others")

    statuses = {
        s["device"]: s["status"]
        for s in client.get("/auth/sessions",
                           headers=auth_header(phone["access_token"])).json()
    }
    assert statuses == {"phone": "active", "laptop": "revoked", "tablet": "revoked"}


def test_logout_all_devices_includes_caller(client):
    phone = login(client, "alice", "alice-pass", device="phone")
    login(client, "alice", "alice-pass", device="laptop")

    resp = client.post(
        "/auth/sessions/logout-others", json={"all_devices": True},
        headers=auth_header(phone["access_token"]),
    )
    assert resp.status_code == 200
    assert resp.json()["revoked"] == 2
    log.info("logout all_devices counted the caller too")
    # the caller's very next access is rejected
    assert client.get("/profile",
                      headers=auth_header(phone["access_token"])).status_code == 401


def test_logout_others_does_not_touch_other_users(client):
    alice = login(client, "alice", "alice-pass", device="alice-a")
    login(client, "alice", "alice-pass", device="alice-b")
    bob = login(client, "bob", "bob-pass", device="bob-a")

    resp = client.post(
        "/auth/sessions/logout-others", json={"all_devices": False},
        headers=auth_header(alice["access_token"]),
    )
    assert resp.json() == {"revoked": 1}
    assert client.get("/profile",
                      headers=auth_header(bob["access_token"])).status_code == 200
    log.info("bulk revoke is scoped to one account")


def test_concurrent_refresh_vs_logout_others_leaves_no_usable_credential(app):
    """Repeat the race many times: regardless of which transaction wins, the
    other device must end up with no usable refresh credential."""
    client = TestClient(app)
    current = login(client, "alice", "alice-pass", device="current")
    login(client, "alice", "alice-pass", device="other")
    auth = app.state.auth
    current_sid = _sid_by_device(client, current["access_token"], "current")

    survived = 0

    for i in range(20):
        # re-create a fresh "other" session each round (it dies each round)
        victim = login(client, "alice", "alice-pass", device=f"victim-{i}")
        vt = victim["refresh_token"]
        refresh_outcome: str | None = None
        new_token: str | None = None

        def do_refresh() -> None:
            nonlocal refresh_outcome, new_token
            try:
                pair = auth.refresh(vt)
                refresh_outcome, new_token = "ok", pair.refresh_token
            except AuthError as exc:
                refresh_outcome = exc.reason.value

        def do_logout() -> None:
            auth.logout_other_devices("alice", current_sid)

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(do_refresh)
            f2 = pool.submit(do_logout)
            f1.result(); f2.result()

        # if refresh won, the token it returned must have been killed by the
        # same-device sweep; a second refresh must never succeed
        if refresh_outcome == "ok":
            try:
                auth.refresh(new_token)  # type: ignore[arg-type]
                survived += 1
            except AuthError:
                pass

    log.info("raced refresh vs logout-others 20 times; surviving credentials=%d", survived)
    assert survived == 0

    # original current device remains usable throughout
    assert client.get("/profile",
                      headers=auth_header(current["access_token"])).status_code == 200
    log.info("after 20 races the current device is intact and no victim survived")
