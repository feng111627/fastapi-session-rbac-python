"""业务：按角色/作用域的细粒度访问控制与伪造声明防护。"""

from __future__ import annotations

import json

from app.security import issue_access_token
from tests.conftest import auth_header, login


def test_admin_can_access_admin_resource(client):
    """【权限边界-允许】admin 访问管理资源 -> 200"""
    token = login(client, "admin", "Admin#123", "desk")
    resp = client.get("/admin", headers=auth_header(token))
    assert resp.status_code == 200
    assert "admin" in resp.json()["message"]


def test_user_cannot_access_admin_resource(client):
    """【权限边界-拒绝】普通 user 访问管理资源 -> 403 forbidden"""
    token = login(client, "alice", "Alice#123", "phone")
    resp = client.get("/admin", headers=auth_header(token))
    assert resp.status_code == 403
    assert resp.json()["error"] == "forbidden"


def test_viewer_can_read_but_cannot_write(client):
    """【权限边界-读/写分离】viewer 可读资料但不能写 -> 读 200 / 写 403"""
    token = login(client, "bob", "Bob#123", "pad")
    assert client.get("/me", headers=auth_header(token)).status_code == 200
    resp = client.post(
        "/me/role", headers=auth_header(token), json={"roles": ["viewer"]}
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "forbidden"


def test_viewer_cannot_revoke_sessions(client):
    """【权限边界-操作级】viewer 无 sessions:revoke -> 403"""
    token = login(client, "bob", "Bob#123", "pad")
    resp = client.post(
        "/sessions/revoke",
        headers=auth_header(token),
        json={"session_id": "whatever"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "forbidden"


def test_user_role_write_takes_effect_and_bounded(client):
    """【权限边界-写入生效】具备写权限的用户更新自身角色 -> 后续按新角色鉴权"""
    token = login(client, "alice", "Alice#123", "phone")
    # user 角色允许 profile:write；降级为 viewer 后失去写权限
    resp = client.post(
        "/me/role", headers=auth_header(token), json={"roles": ["viewer"]}
    )
    assert resp.status_code == 200
    assert resp.json()["roles"] == ["viewer"]
    again = client.post(
        "/me/role", headers=auth_header(token), json={"roles": ["viewer"]}
    )
    assert again.status_code == 403
    # 未知角色被服务端拒绝，无法写入非法声明（用有写权限的会话）
    admin_token = login(client, "admin", "Admin#123", "desk2")
    bad = client.post(
        "/me/role",
        headers=auth_header(admin_token),
        json={"roles": ["superuser"]},
    )
    assert bad.status_code == 400
    assert bad.json()["error"] == "invalid_roles"


def test_forged_role_claim_in_token_cannot_escalate(client, settings):
    """【伪造角色声明】令牌不承载角色；即便自造带 roles 的令牌 -> 仍 401/403"""
    # alice 登录拿会话
    token = login(client, "alice", "Alice#123", "phone")
    # 用合法密钥自签一个“声称是 admin”的访问令牌（注入 roles 声明）
    forged_payload = {
        "iss": settings.issuer,
        "sub": "u_alice",
        "sid": token["session_id"],
        "iat": 1_000_000,
        "exp": 1_000_000 + 900,
        "typ": "access",
        "roles": ["admin"],  # 伪造声明：授权层必须忽略
        "scope": "admin:read",
    }
    import base64
    import hashlib
    import hmac

    body = base64.urlsafe_b64encode(
        json.dumps(forged_payload, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()
    sig = hmac.new(
        settings.secret_key.encode(), body.encode(), hashlib.sha256
    ).digest()
    sig_text = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    forged = f"{body}.{sig_text}"

    resp = client.get("/admin", headers=auth_header(forged))
    # 签名有效、会话存在，但角色以数据库为准（alice 非 admin）-> 403
    assert resp.status_code == 403, resp.text
    assert resp.json()["error"] == "forbidden"


def test_token_signed_with_other_secret_rejected(client):
    """【伪造签名】用其它密钥签发的令牌 -> malformed_token"""
    token = login(client, "alice", "Alice#123", "phone")
    forged = issue_access_token(
        "u_alice",
        token["session_id"],
        "attacker-secret",
        ttl_seconds=900,
        issuer=client.app.state.service.settings.issuer,
        now=1_000_000.0,
    )
    resp = client.get("/me", headers=auth_header(forged))
    assert resp.status_code == 401
    assert resp.json()["error"] == "malformed_token"


def test_access_denied_for_unknown_subject(client, settings):
    """【伪造主体】令牌指向不存在的用户 -> malformed_token"""
    token = issue_access_token(
        "u_ghost",
        "nonexistent-session",
        settings.secret_key,
        ttl_seconds=900,
        issuer=settings.issuer,
        now=1_000_000.0,
    )
    resp = client.get("/me", headers=auth_header(token))
    assert resp.status_code == 401
    assert resp.json()["error"] == "malformed_token"
