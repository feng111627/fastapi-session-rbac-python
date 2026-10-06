"""Shared fixtures: temp DB, app factory, test client."""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

logging.getLogger("auth").setLevel(logging.INFO)


@pytest.fixture()
def settings(tmp_path):
    return Settings(db_path=str(tmp_path / "auth.db"))


@pytest.fixture()
def app(settings):
    return create_app(settings)


@pytest.fixture()
def client(app):
    return TestClient(app)


def login(client: TestClient, username: str, password: str, device: str = "test") -> dict:
    resp = client.post("/auth/login",
                       json={"username": username, "password": password, "device": device})
    assert resp.status_code == 200, resp.text
    return resp.json()


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
