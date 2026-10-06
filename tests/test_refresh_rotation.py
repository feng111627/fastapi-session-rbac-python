"""Refresh token rotation: single-flight rotation + concurrent reuse detection."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.errors import AuthError, Reason
from tests.conftest import auth_header, login

log = logging.getLogger("test.refresh_rotation")


def test_refresh_rotates_token(client):
    pair = login(client, "alice", "alice-pass")
    resp = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.status_code == 200
    new_pair = resp.json()
    assert new_pair["refresh_token"] != pair["refresh_token"]
    log.info("rotation issued a new refresh token")
    # new access token works
    resp = client.get("/profile", headers=auth_header(new_pair["access_token"]))
    assert resp.status_code == 200


def test_reused_refresh_token_is_rejected_and_session_revoked(client):
    pair = login(client, "alice", "alice-pass")
    first = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert first.status_code == 200
    # replaying the old token is detected as reuse
    replay = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert replay.status_code == 401
    assert replay.json()["error"] == Reason.REFRESH_REUSE_DETECTED
    log.info("reuse detected; whole session family must be revoked")
    # the token minted by the legitimate first refresh is now dead too
    again = client.post("/auth/refresh", json={"refresh_token": first.json()["refresh_token"]})
    assert again.status_code == 401
    assert again.json()["error"] == Reason.TOKEN_INVALID
    # and the access token from that session is revoked as well
    resp = client.get("/profile", headers=auth_header(first.json()["access_token"]))
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.TOKEN_REVOKED


def test_concurrent_refresh_reuse_allows_exactly_one_winner(app):
    """N concurrent refreshes of the same token: at most one succeeds, and the
    session is revoked by reuse detection so no two valid tokens coexist."""
    from fastapi.testclient import TestClient

    client = TestClient(app)
    pair = login(client, "alice", "alice-pass")
    auth = app.state.auth
    token = pair["refresh_token"]

    results: list[str] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        def attempt(_: int) -> str:
            try:
                auth.refresh(token)
                return "ok"
            except AuthError as exc:
                return exc.reason.value
        results = list(pool.map(attempt, range(8)))

    winners = results.count("ok")
    losers = [r for r in results if r != "ok"]
    log.info("concurrent refresh results: winners=%d all=%s", winners, results)
    # exactly one rotation wins; every loser gets a distinguishable rejection
    # (reuse detected, or the family was already revoked/cleaned up)
    assert winners == 1
    assert set(losers) <= {
        Reason.REFRESH_REUSE_DETECTED, Reason.TOKEN_INVALID, Reason.SESSION_REVOKED,
    }
    # session revoked: the winner's new refresh token must not be usable
    # (reuse detection kills the whole family)
    sessions = auth.list_sessions("alice")
    assert all(s.revoked for s in sessions)


def test_unknown_refresh_token_rejected(client):
    resp = client.post("/auth/refresh", json={"refresh_token": "no-such-token"})
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.TOKEN_INVALID


def test_expired_refresh_token_rejected(app):
    import time

    from app.tokens import hash_refresh_token

    auth = app.state.auth
    pair = auth.login("alice", "alice-pass")
    # backdate the stored refresh token into expiry
    store = app.state.store
    store._conn.execute(
        "UPDATE refresh_tokens SET expires_at=? WHERE token_hash=?",
        (time.time() - 10, hash_refresh_token(pair.refresh_token)),
    )
    store._conn.commit()
    with pytest.raises(AuthError) as err:
        auth.refresh(pair.refresh_token)
    assert err.value.reason == Reason.TOKEN_EXPIRED
    log.info("expired refresh token rejected with token_expired")
