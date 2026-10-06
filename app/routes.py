"""HTTP 路由：登录、刷新、登出、会话管理、受保护资源。

存储层瞬时异常（DatabaseError）在此统一归一化为 503
storage_unavailable，不向客户端透出底层错误细节。
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.database import DatabaseError
from app.deps import get_service, require_permission
from app.errors import ERR_STORAGE_UNAVAILABLE, AuthError
from app.models import SessionRecord, TokenBundle, UserRecord
from app.rbac import ROLE_PERMISSIONS
from app.schemas import (
    LoginRequest,
    LogoutRequest,
    MeResponse,
    RefreshRequest,
    RevokeRequest,
    RoleRequest,
    SessionInfo,
    TokenResponse,
)

router = APIRouter()


def _to_token_response(service: Any, bundle: TokenBundle) -> TokenResponse:
    return TokenResponse(
        access_token=bundle.access_token,
        refresh_token=bundle.refresh_token,
        session_id=bundle.session.id,
        device_name=bundle.session.device_name,
        expires_in=service.settings.access_token_ttl_seconds,
    )


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/auth/login", response_model=TokenResponse)
def login(
    body: LoginRequest, service: Any = Depends(get_service)
) -> TokenResponse:
    try:
        bundle = service.login(body.username, body.password, body.device_name)
    except DatabaseError as exc:
        raise AuthError(
            ERR_STORAGE_UNAVAILABLE,
            "登录服务暂时不可用，请稍后重试",
            status_code=503,
        ) from exc
    return _to_token_response(service, bundle)


@router.post("/auth/refresh", response_model=TokenResponse)
def refresh(
    body: RefreshRequest, service: Any = Depends(get_service)
) -> TokenResponse:
    try:
        bundle = service.refresh(body.refresh_token)
    except DatabaseError as exc:
        raise AuthError(
            ERR_STORAGE_UNAVAILABLE,
            "令牌服务暂时不可用，请稍后重试",
            status_code=503,
        ) from exc
    return _to_token_response(service, bundle)


@router.post("/auth/logout")
def logout(
    body: LogoutRequest, service: Any = Depends(get_service)
) -> dict[str, str]:
    try:
        service.logout(body.refresh_token)
    except DatabaseError as exc:
        raise AuthError(
            ERR_STORAGE_UNAVAILABLE,
            "登出服务暂时不可用，请稍后重试",
            status_code=503,
        ) from exc
    return {"status": "ok"}


@router.get("/sessions", response_model=list[SessionInfo])
def list_sessions(
    principal: tuple[UserRecord, SessionRecord] = Depends(
        require_permission("sessions:read")
    ),
    service: Any = Depends(get_service),
) -> list[SessionInfo]:
    user, _ = principal
    try:
        sessions = service.list_sessions(user)
    except DatabaseError as exc:
        raise AuthError(
            ERR_STORAGE_UNAVAILABLE,
            "会话查询暂时不可用，请稍后重试",
            status_code=503,
        ) from exc
    return [
        SessionInfo(
            id=s.id,
            device_name=s.device_name,
            revoked=s.revoked,
            created_at=s.created_at,
            last_rotated_at=s.last_rotated_at,
            refresh_expires_at=s.refresh_expires_at,
        )
        for s in sessions
    ]


@router.post("/sessions/revoke")
def revoke_session(
    body: RevokeRequest,
    principal: tuple[UserRecord, SessionRecord] = Depends(
        require_permission("sessions:revoke")
    ),
    service: Any = Depends(get_service),
) -> dict[str, object]:
    user, _ = principal
    try:
        changed = service.revoke_session(user, body.session_id)
    except DatabaseError as exc:
        raise AuthError(
            ERR_STORAGE_UNAVAILABLE,
            "吊销操作暂时不可用，请稍后重试",
            status_code=503,
        ) from exc
    return {"status": "ok", "revoked": changed}


@router.get("/me", response_model=MeResponse)
def read_me(
    principal: tuple[UserRecord, SessionRecord] = Depends(
        require_permission("profile:read")
    ),
) -> MeResponse:
    user, session = principal
    from app.rbac import permissions_for_roles

    return MeResponse(
        user_id=user.id,
        username=user.username,
        roles=user.roles,
        session_id=session.id,
        device_name=session.device_name,
        permissions=sorted(permissions_for_roles(user.roles)),
    )


@router.post("/me/role", response_model=MeResponse)
def write_role(
    body: RoleRequest,
    principal: tuple[UserRecord, SessionRecord] = Depends(
        require_permission("profile:write")
    ),
    service: Any = Depends(get_service),
) -> MeResponse:
    """更新本人角色（演示写权限边界）。

    服务端强制角色必须存在于已知角色表，无法通过此接口伪造
    admin 之外的非法声明；真正的提权仍需 admin 权限资源。
    """
    user, session = principal
    invalid = [r for r in body.roles if r not in ROLE_PERMISSIONS]
    if invalid:
        raise AuthError(
            "invalid_roles", f"未知角色: {','.join(invalid)}", status_code=400
        )
    try:
        service.store.update_user_roles(user.id, body.roles)
        user = service.store.get_user_by_id(user.id)
    except DatabaseError as exc:
        raise AuthError(
            ERR_STORAGE_UNAVAILABLE,
            "资料更新暂时不可用，请稍后重试",
            status_code=503,
        ) from exc
    from app.rbac import permissions_for_roles

    return MeResponse(
        user_id=user.id,
        username=user.username,
        roles=user.roles,
        session_id=session.id,
        device_name=session.device_name,
        permissions=sorted(permissions_for_roles(user.roles)),
    )


@router.get("/admin")
def read_admin(
    principal: tuple[UserRecord, SessionRecord] = Depends(
        require_permission("admin:read")
    ),
) -> dict[str, str]:
    user, _ = principal
    return {"message": f"欢迎管理员 {user.username}"}
