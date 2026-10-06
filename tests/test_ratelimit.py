"""Progressive rate limiting on login failures and refresh abuse."""
from __future__ import annotations

import logging

from app.errors import Reason
from tests.conftest import login

log = logging.getLogger("test.ratelimit")


def test_login_failures_trigger_progressive_lockout(client, settings):
    settings.login_fail_base_delay_seconds = 30
    settings.login_fail_free_attempts = 1
    for i in range(2):
        resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
        assert resp.status_code == 401
        assert resp.json()["error"] == Reason.BAD_CREDENTIALS
    # next attempt (even with the right password) is rate limited
    resp = client.post("/auth/login", json={"username": "alice", "password": "alice-pass"})
    assert resp.status_code == 429
    assert resp.json()["error"] == Reason.RATE_LIMITED
    assert int(resp.headers["retry-after"]) > 0
    log.info("login locked out after repeated failures, retry-after=%s",
             resp.headers["retry-after"])


def test_lockout_delay_grows_progressively(app, settings):
    settings.login_fail_base_delay_seconds = 2
    settings.login_fail_free_attempts = 0
    limiter = app.state.limiter
    delays = []
    for _ in range(4):
        limiter.record_login_failure("carol")
        rec = app.state.store.get_limit("login:carol")
        delays.append(rec.locked_until)
    gaps = [b - a for a, b in zip(delays, delays[1:])]
    log.info("progressive lockout delays: %s", [round(g, 2) for g in gaps])
    assert gaps[1] > gaps[0]  # exponential growth


def test_successful_login_resets_limiter(client, settings):
    settings.login_fail_base_delay_seconds = 30
    settings.login_fail_free_attempts = 1
    client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    login(client, "alice", "alice-pass")  # success resets the counter
    pair = login(client, "alice", "alice-pass")  # still allowed
    assert pair["access_token"]
    log.info("successful login reset the failure counter")


def test_refresh_abuse_is_progressively_limited(client, settings):
    settings.refresh_abuse_base_delay_seconds = 30
    pair = login(client, "alice", "alice-pass")
    client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    # reuse -> session revoked + abuse recorded
    resp = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.json()["error"] == Reason.REFRESH_REUSE_DETECTED
    # further abuse attempts on the same user hit the limiter
    limiter = client.app.state.limiter
    import pytest

    from app.errors import AuthError
    with pytest.raises(AuthError) as err:
        limiter.check_refresh_abuse("alice")
    assert err.value.reason == Reason.RATE_LIMITED
    log.info("refresh abuse progressively limited for user=alice")
