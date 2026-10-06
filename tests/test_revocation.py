"""业务：登出、主动吊销与多设备会话管理，吊销后入口立即失效。"""

from __future__ import annotations

from tests.conftest import auth_header, login


def test_logout_revokes_access_immediately(client):
    """【登出即失效】登出后旧访问令牌与刷新令牌立即失效 -> session_revoked"""
    token = login(client, "alice", "Alice#123", "phone")
    headers = auth_header(token)
    assert client.get("/me", headers=headers).status_code == 200

    assert (
        client.post(
            "/auth/logout", json={"refresh_token": token["refresh_token"]}
        ).status_code
        == 200
    )
    # 访问入口立即失效（即使 access token 自身尚未过期）
    resp = client.get("/me", headers=headers)
    assert resp.status_code == 401
    assert resp.json()["error"] == "session_revoked"
    # 刷新入口同样失效
    resp = client.post(
        "/auth/refresh", json={"refresh_token": token["refresh_token"]}
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "session_revoked"


def test_owner_revoke_other_device_session(client):
    """【多设备吊销】列出多设备会话并吊销其中一台 -> 该台立即失效，其它仍有效"""
    phone = login(client, "alice", "Alice#123", "phone")
    laptop = login(client, "alice", "Alice#123", "laptop")

    sessions = client.get(
        "/sessions", headers=auth_header(phone)
    ).json()
    devices = {s["device_name"]: s for s in sessions}
    assert set(devices) >= {"phone", "laptop"}

    # phone 吊销 laptop 的会话
    resp = client.post(
        "/sessions/revoke",
        headers=auth_header(phone),
        json={"session_id": devices["laptop"]["id"]},
    )
    assert resp.status_code == 200
    assert resp.json()["revoked"] is True

    # laptop 立即失效
    blocked = client.get("/me", headers=auth_header(laptop))
    assert blocked.status_code == 401
    assert blocked.json()["error"] == "session_revoked"
    # phone 仍然有效
    assert client.get("/me", headers=auth_header(phone)).status_code == 200


def test_cannot_revoke_other_users_session(client):
    """【越权吊销】用户不能吊销他人会话 -> 返回未生效，他人会话不受影响"""
    alice = login(client, "alice", "Alice#123", "phone")
    bob = login(client, "bob", "Bob#123", "pad")

    bob_sessions = client.get(
        "/sessions", headers=auth_header(bob)
    ).json()
    bob_sid = bob_sessions[0]["id"]

    resp = client.post(
        "/sessions/revoke",
        headers=auth_header(alice),
        json={"session_id": bob_sid},
    )
    assert resp.status_code == 200
    assert resp.json()["revoked"] is False
    # bob 依然可用
    assert client.get("/me", headers=auth_header(bob)).status_code == 200


def test_revoke_idempotent(client):
    """【吊销幂等】重复吊销返回未变更，但会话保持失效状态"""
    token = login(client, "alice", "Alice#123", "phone")
    sid = token["session_id"]
    first = client.post(
        "/sessions/revoke",
        headers=auth_header(token),
        json={"session_id": sid},
    )
    assert first.json()["revoked"] is True
    second = client.post(
        "/sessions/revoke",
        headers=auth_header(login(client, "alice", "Alice#123", "phone2")),
        json={"session_id": sid},
    )
    assert second.json()["revoked"] is False


def test_refresh_family_revoked_after_reuse_blocks_new_token(client):
    """【异常使用处置】旧令牌重用 -> 整个刷新族（含轮换后的新令牌）失效"""
    token = login(client, "alice", "Alice#123", "phone")
    rotated = client.post(
        "/auth/refresh", json={"refresh_token": token["refresh_token"]}
    ).json()
    # 攻击者重放旧令牌
    replay = client.post(
        "/auth/refresh", json={"refresh_token": token["refresh_token"]}
    )
    assert replay.status_code == 401
    assert replay.json()["error"] == "refresh_token_reused"
    # 合法用户手里的新令牌也被族吊销阻断
    resp = client.post(
        "/auth/refresh", json={"refresh_token": rotated["refresh_token"]}
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "session_revoked"


def test_missing_token_distinguishable(client):
    """【缺失令牌】不带 Authorization -> missing_token，与吊销/过期区分"""
    resp = client.get("/sessions")
    assert resp.status_code == 401
    assert resp.json()["error"] == "missing_token"
