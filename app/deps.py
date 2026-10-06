"""FastAPI 依赖：解析访问令牌、实时加载用户与会话、鉴权。

访问令牌虽为自包含签名令牌，但每次请求都会：
1. 校验签名与有效期；
2. 按 sid 从数据库读取会话，确认未被吊销（吊销立即生效）；
3. 按 sub 从数据库实时加载用户角色（角色不取自令牌，杜绝伪造）。
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, Header, Request

from app.database import DatabaseError
from app.errors import (
    ERR_FORBIDDEN,
    ERR_MALFORMED_TOKEN,
    ERR_MISSING_TOKEN,
    ERR_SESSION_REVOKED,
    ERR_STORAGE_UNAVAILABLE,
    AuthError,
)
from app.models import SessionRecord, UserRecord
from app.rbac import has_permission
from app.security import verify_access_token

BEARER_PREFIX = "Bearer "


def get_service(request: Request) -> Any:
    """从应用状态取认证服务（由 create_app 装配）。"""
    service = getattr(request.app.state, "service", None)
    if service is None:  # pragma: no cover - 装配错误属于编程问题
        raise AuthError(
            ERR_STORAGE_UNAVAILABLE, "认证服务未就绪", status_code=503
        )
    return service


def _extract_bearer(authorization: str | None) -> str:
    if not authorization:
        raise AuthError(
            ERR_MISSING_TOKEN, "缺少 Authorization 访问令牌", status_code=401
        )
    if not authorization.startswith(BEARER_PREFIX):
        raise AuthError(
            ERR_MALFORMED_TOKEN,
            "Authorization 头必须使用 Bearer 方案",
            status_code=401,
        )
    token = authorization[len(BEARER_PREFIX):].strip()
    if not token:
        raise AuthError(
            ERR_MISSING_TOKEN, "访问令牌为空", status_code=401
        )
    return token


async def get_current_principal(
    request: Request,
    authorization: str | None = Header(default=None),
    service: Any = Depends(get_service),
) -> tuple[UserRecord, SessionRecord]:
    """返回 (用户, 会话)；失败以可区分 code 抛 AuthError。"""
    token = _extract_bearer(authorization)
    claims = verify_access_token(
        token,
        service.settings.secret_key,
        expected_issuer=service.settings.issuer,
        now=service._now(),
    )
    try:
        user = service.store.get_user_by_id(claims["sub"])
        # 会话实时校验：吊销/登出后即使访问令牌未过期也立即失效
        sessions = service.store.list_sessions(claims["sub"])
    except DatabaseError as exc:
        raise AuthError(
            ERR_STORAGE_UNAVAILABLE,
            "认证依赖暂时不可用，请稍后重试",
            status_code=503,
        ) from exc

    session = next((s for s in sessions if s.id == claims["sid"]), None)
    if user is None or session is None:
        raise AuthError(
            ERR_MALFORMED_TOKEN, "令牌对应的主体或会话不存在", status_code=401
        )
    if session.revoked:
        raise AuthError(
            ERR_SESSION_REVOKED, "会话已被吊销", status_code=401
        )
    request.state.principal = (user, session)
    return user, session


def require_permission(permission: str):
    """依赖工厂：校验实时加载的角色是否满足指定权限。"""

    async def _checker(
        principal: tuple[UserRecord, SessionRecord] = Depends(
            get_current_principal
        ),
    ) -> tuple[UserRecord, SessionRecord]:
        user, session = principal
        if not has_permission(user.roles, permission):
            raise AuthError(
                ERR_FORBIDDEN,
                f"缺少所需权限: {permission}",
                status_code=403,
            )
        return user, session

    return _checker
