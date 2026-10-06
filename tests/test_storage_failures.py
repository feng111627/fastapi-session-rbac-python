"""Storage/dependency failures are normalized, never leaked raw."""
from __future__ import annotations

import logging

from app.errors import Reason, StorageError
from tests.conftest import login

log = logging.getLogger("test.storage")


def test_storage_error_normalized_on_login(client, monkeypatch):
    def boom(*args, **kwargs):
        raise StorageError("disk on fire: /secret/internal/path") from OSError("io detail")

    monkeypatch.setattr(client.app.state.store, "get_user", boom)
    resp = client.post("/auth/login", json={"username": "alice", "password": "alice-pass"})
    assert resp.status_code == 503
    assert resp.json() == {"error": Reason.STORAGE_UNAVAILABLE}
    assert "disk on fire" not in resp.text and "OSError" not in resp.text
    log.info("storage failure normalized to 503 storage_unavailable without internals")


def test_storage_error_normalized_on_refresh(client, monkeypatch):
    pair = login(client, "alice", "alice-pass")

    def boom(*args, **kwargs):
        raise StorageError("sqlite3.OperationalError: database is locked")

    monkeypatch.setattr(client.app.state.store, "rotate_refresh_token", boom)
    resp = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert resp.status_code == 503
    assert resp.json() == {"error": Reason.STORAGE_UNAVAILABLE}
    assert "sqlite3" not in resp.text
    log.info("refresh storage failure normalized to 503 without driver details")


def test_storage_error_normalized_on_protected_route(client, monkeypatch):
    pair = login(client, "alice", "alice-pass")

    def boom(*args, **kwargs):
        raise StorageError("connection reset by peer 10.0.0.9")

    monkeypatch.setattr(client.app.state.store, "get_session", boom)
    resp = client.get("/profile",
                      headers={"Authorization": f"Bearer {pair['access_token']}"})
    assert resp.status_code == 503
    assert resp.json() == {"error": Reason.STORAGE_UNAVAILABLE}
    assert "10.0.0.9" not in resp.text
    log.info("protected-route storage failure normalized to 503")
