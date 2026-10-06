"""业务：登录失败/刷新异常使用的递进限制，以及存储异常归一化。"""

from __future__ import annotations

from app.database import DatabaseError
from tests.conftest import auth_header, login


# --------------------------------------------------------------------------
# 登录失败递进限制
# --------------------------------------------------------------------------
def test_login_failures_progressive_then_lock(client):
    """【登录递进限制】连续失败达到阈值前返回凭据错误，达到阈值返回锁定"""
    for i in range(2):
        resp = client.post(
            "/auth/login",
            json={"username": "alice", "password": "bad", "device_name": "x"},
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_credentials"

    locked = client.post(
        "/auth/login",
        json={"username": "alice", "password": "bad", "device_name": "x"},
    )
    assert locked.status_code == 429
    assert locked.json()["error"] == "login_locked"

    # 锁定期间即使密码正确也不放行
    correct = client.post(
        "/auth/login",
        json={
            "username": "alice",
            "password": "Alice#123",
            "device_name": "x",
        },
    )
    assert correct.status_code == 429
    assert correct.json()["error"] == "login_locked"


def test_login_lock_resets_after_window(client, clock):
    """【登录递进限制-窗口】超出锁定窗口后计数失效，可重新登录"""
    for _ in range(3):
        client.post(
            "/auth/login",
            json={"username": "alice", "password": "bad", "device_name": "x"},
        )
    assert (
        client.post(
            "/auth/login",
            json={
                "username": "alice",
                "password": "Alice#123",
                "device_name": "x",
            },
        ).status_code
        == 429
    )
    clock.advance(901)  # 超过 login_lock_window_seconds
    resp = client.post(
        "/auth/login",
        json={
            "username": "alice",
            "password": "Alice#123",
            "device_name": "x",
        },
    )
    assert resp.status_code == 200


def test_login_failure_counter_scoped_per_username(client):
    """【登录递进限制-隔离】一个用户被锁不影响其它用户登录"""
    for _ in range(3):
        client.post(
            "/auth/login",
            json={"username": "alice", "password": "bad", "device_name": "x"},
        )
    bob = client.post(
        "/auth/login",
        json={"username": "bob", "password": "Bob#123", "device_name": "pad"},
    )
    assert bob.status_code == 200


def test_successful_login_clears_failures(client):
    """【登录递进限制-清零】失败后成功登录会清零计数"""
    client.post(
        "/auth/login",
        json={"username": "alice", "password": "bad", "device_name": "x"},
    )
    assert (
        client.post(
            "/auth/login",
            json={
                "username": "alice",
                "password": "Alice#123",
                "device_name": "x",
            },
        ).status_code
        == 200
    )
    # 再来两次错误不应被锁（计数已清空，阈值为 3）
    for _ in range(2):
        resp = client.post(
            "/auth/login",
            json={
                "username": "alice",
                "password": "bad",
                "device_name": "x",
            },
        )
        assert resp.status_code == 401


# --------------------------------------------------------------------------
# 刷新异常使用递进限制
# --------------------------------------------------------------------------
def test_refresh_abuse_locks_family_after_threshold(client, service, clock):
    """【刷新递进限制】窗口内异常使用累计达到阈值 -> refresh_locked"""
    token = login(client, "alice", "Alice#123", "phone")
    family = service.store.list_sessions("u_alice")[0].refresh_family
    # 先记到阈值（模拟此前已发生过若干次旧令牌重用）
    for _ in range(service.settings.refresh_max_abuses):
        service.store.record_refresh_abuse(family, clock())

    resp = client.post(
        "/auth/refresh", json={"refresh_token": token["refresh_token"]}
    )
    # 即使提交的是当前有效令牌，族滥用计数已达阈值也先锁定
    assert resp.status_code == 429
    assert resp.json()["error"] == "refresh_locked"


def test_refresh_below_threshold_still_rotates(client, service, clock):
    """【刷新递进限制】未达阈值时正常轮换不受影响"""
    token = login(client, "alice", "Alice#123", "phone")
    family = service.store.list_sessions("u_alice")[0].refresh_family
    for _ in range(service.settings.refresh_max_abuses - 1):
        service.store.record_refresh_abuse(family, clock())
    resp = client.post(
        "/auth/refresh", json={"refresh_token": token["refresh_token"]}
    )
    assert resp.status_code == 200, resp.text


def test_refresh_abuse_window_expires(client, service, clock):
    """【刷新递进限制-窗口】超出窗口后滥用计数归零，恢复正常轮换"""
    token = login(client, "alice", "Alice#123", "phone")
    family = service.store.list_sessions("u_alice")[0].refresh_family
    for _ in range(service.settings.refresh_max_abuses):
        service.store.record_refresh_abuse(family, clock())
    assert (
        client.post(
            "/auth/refresh", json={"refresh_token": token["refresh_token"]}
        ).status_code
        == 429
    )
    clock.advance(service.settings.refresh_lock_window_seconds + 1)
    resp = client.post(
        "/auth/refresh", json={"refresh_token": token["refresh_token"]}
    )
    assert resp.status_code == 200


# --------------------------------------------------------------------------
# 存储瞬时异常归一化
# --------------------------------------------------------------------------
class FlakyStore:
    """对指定方法抛出 DatabaseError 的瞬时故障代理。"""

    def __init__(self, real_store, failing_methods):
        self._real = real_store
        self._failing = set(failing_methods)

    def __getattr__(self, name):
        attr = getattr(self._real, name)
        if name in self._failing and callable(attr):
            def boom(*args, **kwargs):
                raise DatabaseError("simulated transient sqlite error")
            return boom
        return attr


def test_storage_error_on_login_normalized(client, monkeypatch):
    """【存储异常归一化-登录】登录路径存储故障 -> 503 storage_unavailable"""
    service = client.app.state.service
    monkeypatch.setattr(
        service, "store", FlakyStore(service.store, ["get_user_by_username"])
    )
    resp = client.post(
        "/auth/login",
        json={
            "username": "alice",
            "password": "Alice#123",
            "device_name": "x",
        },
    )
    assert resp.status_code == 503
    body = resp.json()
    assert body["error"] == "storage_unavailable"
    assert "sqlite" not in body["error_description"]


def test_storage_error_on_protected_resource_normalized(client, monkeypatch):
    """【存储异常归一化-访问】资源访问时存储故障 -> 503 且不泄露内部细节"""
    token = login(client, "alice", "Alice#123", "phone")
    service = client.app.state.service
    monkeypatch.setattr(
        service, "store", FlakyStore(service.store, ["get_user_by_id"])
    )
    resp = client.get("/me", headers=auth_header(token))
    assert resp.status_code == 503
    body = resp.json()
    assert body["error"] == "storage_unavailable"
    assert "Traceback" not in resp.text
