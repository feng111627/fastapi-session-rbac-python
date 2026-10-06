"""密码哈希、令牌哈希与访问令牌签发/校验。

不依赖外部 JWT 库：访问令牌为 ``base64url(payload).base64url(sig)``
形式的 HMAC-SHA256 签名令牌。令牌只承载用户/会话标识与过期时间，
**不承载角色声明**——授权一律以数据库实时加载的角色为准，
因此无法通过伪造令牌内容越权。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid

from app.errors import (
    ERR_MALFORMED_TOKEN,
    ERR_TOKEN_EXPIRED,
    AuthError,
)

_PBKDF2_ALGO = "pbkdf2_sha256"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


# --------------------------------------------------------------------------
# 密码：PBKDF2-HMAC-SHA256，格式 algo$iterations$salt_b64$hash_b64
# --------------------------------------------------------------------------
def hash_password(password: str, *, iterations: int = 200_000) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return f"{_PBKDF2_ALGO}${iterations}${_b64e(salt)}${_b64e(digest)}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algo, iter_text, salt_text, hash_text = password_hash.split("$", 3)
        if algo != _PBKDF2_ALGO:
            return False
        iterations = int(iter_text)
        salt = _b64d(salt_text)
        expected = _b64d(hash_text)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(candidate, expected)


def sha256_hex(value: str) -> str:
    """对刷新令牌等不透明凭据做存储哈希（落库的是哈希而非明文）。"""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_refresh_token() -> str:
    """生成高熵不透明刷新令牌（仅明文出现一次并返回给客户端）。"""
    return _b64e(os.urandom(32))


# --------------------------------------------------------------------------
# 访问令牌：自包含签名令牌
# --------------------------------------------------------------------------
def issue_access_token(
    user_id: str,
    session_id: str,
    secret: str,
    *,
    ttl_seconds: int,
    issuer: str,
    now: float | None = None,
) -> str:
    issued_at = int(now if now is not None else time.time())
    payload = {
        "iss": issuer,
        "sub": user_id,
        "sid": session_id,
        "iat": issued_at,
        "exp": issued_at + int(ttl_seconds),
        "typ": "access",
        # 每次签发唯一：即使同一秒内重签，令牌也不同
        "jti": uuid.uuid4().hex,
    }
    body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256)
    return f"{body}.{_b64e(sig.digest())}"


def verify_access_token(
    token: str,
    secret: str,
    *,
    expected_issuer: str | None = None,
    now: float | None = None,
) -> dict:
    """校验签名与有效期，返回 claims。

    失败时以可区分的 code 抛 AuthError：
    - malformed_token：结构错误 / 签名不符 / 声明非法
    - token_expired ：签名有效但已过期
    """
    parts = token.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise AuthError(ERR_MALFORMED_TOKEN, "令牌格式不正确", status_code=401)
    body, sig_text = parts
    expected_sig = hmac.new(
        secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256
    ).digest()
    try:
        if not hmac.compare_digest(_b64d(sig_text), expected_sig):
            raise AuthError(ERR_MALFORMED_TOKEN, "令牌签名无效", status_code=401)
        payload = json.loads(_b64d(body))
    except AuthError:
        raise
    except Exception:
        raise AuthError(ERR_MALFORMED_TOKEN, "令牌内容无法解析", status_code=401)

    if not isinstance(payload, dict) or not {"iss", "sub", "sid", "exp"} <= payload.keys():
        raise AuthError(ERR_MALFORMED_TOKEN, "令牌声明不完整", status_code=401)
    if expected_issuer is not None and payload.get("iss") != expected_issuer:
        raise AuthError(ERR_MALFORMED_TOKEN, "令牌签发方不匹配", status_code=401)
    current = time.time() if now is None else now
    if current >= float(payload["exp"]):
        raise AuthError(ERR_TOKEN_EXPIRED, "访问令牌已过期", status_code=401)
    return payload
