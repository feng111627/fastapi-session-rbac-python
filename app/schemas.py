"""HTTP 层 Pydantic 模型。"""

from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    device_name: str = Field(default="unknown", max_length=64)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=256)


class LogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=256)


class RevokeRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=64)


class RoleRequest(BaseModel):
    """测试用：仅允许在本人角色内调整（profile:write 资源）。

    角色修改仍受服务端白名单约束，无法借此提升权限。
    """

    roles: list[str] = Field(min_length=1, max_length=8)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    session_id: str
    device_name: str
    expires_in: int


class SessionInfo(BaseModel):
    id: str
    device_name: str
    revoked: bool
    created_at: float
    last_rotated_at: float
    refresh_expires_at: float


class MeResponse(BaseModel):
    user_id: str
    username: str
    roles: list[str]
    session_id: str
    device_name: str
    permissions: list[str]


class ErrorResponse(BaseModel):
    error: str
    error_description: str
