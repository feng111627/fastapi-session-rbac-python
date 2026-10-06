"""业务：刷新令牌轮换与并发重复使用。"""

from __future__ import annotations

import threading

import pytest

from app.errors import AuthError
from tests.conftest import auth_header, login


def test_refresh_rotates_tokens(client, alice):
    """【刷新令牌轮换】正常刷新签发新令牌对 -> 得到新的访问/刷新令牌"""
    resp = client.post(
        "/auth/refresh", json={"refresh_token": alice["refresh_token"]}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"] != alice["access_token"]
    assert body["refresh_token"] != alice["refresh_token"]
    assert body["session_id"] == alice["session_id"]


def test_refresh_new_token_works_old_one_rejected(client, alice):
    """【刷新令牌轮换】轮换后新令牌可用、旧令牌被拒 -> 旧判 reused 新判有效"""
    new = client.post(
        "/auth/refresh", json={"refresh_token": alice["refresh_token"]}
    ).json()
    # 新刷新令牌可以继续轮换（正常链）
    again = client.post(
        "/auth/refresh", json={"refresh_token": new["refresh_token"]}
    )
    assert again.status_code == 200

    # 旧令牌再次提交 -> 明确异常使用
    resp = client.post(
        "/auth/refresh", json={"refresh_token": alice["refresh_token"]}
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "refresh_token_reused"


def test_concurrent_refresh_reuse_single_winner(service, alice, client):
    """【并发重复使用】同一刷新令牌并发刷新 -> 仅一次成功，其余判重用且族吊销"""
    original_refresh = alice["refresh_token"]
    results: list[tuple[str, object]] = []
    barrier = threading.Barrier(10)

    def worker():
        barrier.wait()
        try:
            bundle = service.refresh(original_refresh)
            results.append(("ok", bundle.refresh_token))
        except AuthError as exc:
            results.append(("error", exc.code))
        except Exception as exc:  # pragma: no cover
            results.append(("fatal", repr(exc)))

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, results
    assert len(failures) == 9
    # 并发竞态下失败者有三种确定、可区分的结果：
    #  - 检测到旧令牌已轮换 -> refresh_token_reused（异常使用）
    #  - 族已被异常处置吊销 -> session_revoked
    #  - 窗口内滥用累计达阈值 -> refresh_locked（递进限制）
    # 共同保证：不会有第二个新令牌被成功签发。
    codes = {code for _, code in failures}
    assert codes <= {
        "refresh_token_reused",
        "session_revoked",
        "refresh_locked",
    }
    # 至少有一个请求明确识别出“旧令牌重用”
    assert "refresh_token_reused" in codes

    # 唯一成功的新令牌再使用时也不能生效：
    # 族已吊销(session_revoked) 或 滥用递进锁定(refresh_locked)
    winner_refresh = successes[0][1]
    with pytest.raises(AuthError) as ei:
        service.refresh(winner_refresh)
    assert ei.value.code in ("session_revoked", "refresh_locked")


def test_concurrent_refresh_no_two_valid_tokens(client, service, alice):
    """【并发重复使用】并发结果中不会出现两个都有效的新令牌 -> 有效新令牌恰为 1 个"""
    original_refresh = alice["refresh_token"]
    produced: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(12)

    def worker():
        barrier.wait()
        try:
            bundle = service.refresh(original_refresh)
            with lock:
                produced.append(bundle.refresh_token)
        except AuthError:
            pass

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(produced) == 1
    # 事后校验：唯一被接受的新令牌也无法继续使用（族吊销或递进锁定）
    with pytest.raises(AuthError) as ei:
        service.refresh(produced[0])
    assert ei.value.code in ("session_revoked", "refresh_locked")


def test_refresh_after_expiry_distinguished(client, service, alice, clock):
    """【刷新过期】刷新令牌过期 -> 返回 token_expired 而非其它原因"""
    clock.advance(service.settings.refresh_token_ttl_seconds + 1)
    resp = client.post(
        "/auth/refresh", json={"refresh_token": alice["refresh_token"]}
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_expired"


def test_refresh_unknown_token(client):
    """【刷新令牌缺失/伪造】提交未知令牌 -> invalid_credentials"""
    resp = client.post("/auth/refresh", json={"refresh_token": "a" * 43})
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credentials"


def test_access_token_remains_valid_until_expiry(client, clock):
    """【访问令牌生命周期】未过期且会话正常 -> 访问通过；过期 -> token_expired"""
    token = login(client, "alice", "Alice#123", "phone")
    assert client.get("/me", headers=auth_header(token)).status_code == 200
    clock.advance(901)
    resp = client.get("/me", headers=auth_header(token))
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_expired"
