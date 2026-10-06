"""业务：服务重启后会话与吊销状态可恢复（SQLite 持久化）。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.app import create_app
from tests.conftest import auth_header, login


def _new_client(settings, clock):
    app = create_app(settings, clock=clock)
    return TestClient(app)


def test_sessions_survive_restart(client, settings, clock):
    """【重启恢复-会话】重启前登录，重启后访问令牌与刷新令牌继续可用"""
    token = login(client, "alice", "Alice#123", "phone")
    client.__exit__(None, None, None)  # 模拟服务关闭

    with _new_client(settings, clock) as restarted:
        me = restarted.get("/me", headers=auth_header(token))
        assert me.status_code == 200
        assert me.json()["username"] == "alice"

        sessions = restarted.get(
            "/sessions", headers=auth_header(token)
        ).json()
        assert any(s["id"] == token["session_id"] for s in sessions)

        rotated = restarted.post(
            "/auth/refresh", json={"refresh_token": token["refresh_token"]}
        )
        assert rotated.status_code == 200
        assert rotated.json()["session_id"] == token["session_id"]


def test_revocation_survives_restart(client, settings, clock):
    """【重启恢复-吊销】重启前吊销的会话，重启后仍保持吊销"""
    token = login(client, "alice", "Alice#123", "phone")
    client.post(
        "/auth/logout", json={"refresh_token": token["refresh_token"]}
    )
    client.__exit__(None, None, None)

    with _new_client(settings, clock) as restarted:
        resp = restarted.get("/me", headers=auth_header(token))
        assert resp.status_code == 401
        assert resp.json()["error"] == "session_revoked"

        refresh = restarted.post(
            "/auth/refresh", json={"refresh_token": token["refresh_token"]}
        )
        assert refresh.status_code == 401
        assert refresh.json()["error"] == "session_revoked"


def test_multi_device_state_survives_restart(client, settings, clock):
    """【重启恢复-多设备】多设备中一台吊销，重启后吊销设备/存活设备状态保持"""
    phone = login(client, "alice", "Alice#123", "phone")
    laptop = login(client, "alice", "Alice#123", "laptop")
    sessions = client.get("/sessions", headers=auth_header(phone)).json()
    laptop_sid = next(s["id"] for s in sessions if s["device_name"] == "laptop")
    client.post(
        "/sessions/revoke",
        headers=auth_header(phone),
        json={"session_id": laptop_sid},
    )
    client.__exit__(None, None, None)

    with _new_client(settings, clock) as restarted:
        assert (
            restarted.get("/me", headers=auth_header(phone)).status_code == 200
        )
        blocked = restarted.get("/me", headers=auth_header(laptop))
        assert blocked.status_code == 401
        assert blocked.json()["error"] == "session_revoked"

        sessions2 = restarted.get(
            "/sessions", headers=auth_header(phone)
        ).json()
        by_id = {s["id"]: s for s in sessions2}
        assert by_id[phone["session_id"]]["revoked"] is False
        assert by_id[laptop_sid]["revoked"] is True


def test_login_lockout_state_survives_restart(client, settings, clock):
    """【重启恢复-锁定】重启前登录失败计数已积累，重启后继续计数直至锁定"""
    for _ in range(2):
        client.post(
            "/auth/login",
            json={"username": "alice", "password": "wrong", "device_name": "x"},
        )
    client.__exit__(None, None, None)

    with _new_client(settings, clock) as restarted:
        resp = restarted.post(
            "/auth/login",
            json={"username": "alice", "password": "wrong", "device_name": "x"},
        )
        assert resp.status_code == 429
        assert resp.json()["error"] == "login_locked"
