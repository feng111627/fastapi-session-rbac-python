"""应用配置：所有可调参数集中在此，支持环境变量覆盖。

环境变量统一以 ``AUTH_`` 前缀命名，例如
``AUTH_ACCESS_TOKEN_TTL_SECONDS=300``。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, fields


@dataclass(frozen=True)
class Settings:
    # SQLite 连接 URL，形如 sqlite:////abs/path.db 或 sqlite:///./rel.db
    database_url: str = "sqlite:///./data/auth.db"
    # 访问令牌签名密钥；生产部署必须通过 AUTH_SECRET_KEY 覆盖
    secret_key: str = "dev-only-insecure-secret-change-me"
    # 访问令牌有效期（秒）
    access_token_ttl_seconds: int = 900
    # 刷新令牌有效期（秒）：默认 14 天
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 14
    issuer: str = "fastapi-session-rbac"
    # 登录失败递进锁定：窗口内容许的最大失败次数与窗口长度
    login_max_failures: int = 5
    login_lock_window_seconds: int = 900
    # 刷新令牌异常使用（旧令牌被再次提交）的递进限制
    refresh_max_abuses: int = 3
    refresh_lock_window_seconds: int = 1800
    # PBKDF2 迭代轮数（测试可调低）
    password_pbkdf2_iterations: int = 200_000


def _coerce(value: str, target_type: type):
    if target_type is int:
        return int(value)
    if target_type is bool:
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return value


def get_settings() -> Settings:
    """从环境变量读取配置；缺省时使用开发默认值。"""
    kwargs: dict[str, object] = {}
    for f in fields(Settings):
        env_name = "AUTH_" + f.name.upper()
        if env_name in os.environ:
            kwargs[f.name] = _coerce(os.environ[env_name], f.type)
    return Settings(**kwargs)
