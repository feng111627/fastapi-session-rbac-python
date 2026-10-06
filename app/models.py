"""持久层数据模型与会话仓储接口。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class UserRecord:
    id: str
    username: str
    password_hash: str
    roles: list[str]


@dataclass
class SessionRecord:
    id: str
    user_id: str
    device_name: str
    refresh_family: str
    refresh_token_hash: str
    refresh_expires_at: float
    revoked: bool
    created_at: float
    last_rotated_at: float


class SessionStore:
    """仓储协议（结构化类型，SqliteStore 满足该接口）。"""

    def init_schema(self) -> None: ...
    def create_user(self, user: UserRecord) -> None: ...
    def seed_users(self, users: list[UserRecord]) -> None: ...
    def get_user_by_username(self, username: str) -> UserRecord | None: ...
    def get_user_by_id(self, user_id: str) -> UserRecord | None: ...
    def update_user_roles(self, user_id: str, roles: list[str]) -> None: ...
    def list_sessions(self, user_id: str) -> list[SessionRecord]: ...
    def create_session(self, session: SessionRecord) -> None: ...
    def find_session_by_refresh_hash(self, token_hash: str) -> SessionRecord | None: ...
    def rotate_refresh(
        self, token_hash: str, new_hash: str, new_expires_at: float, now: float
    ) -> tuple[str, SessionRecord | None]: ...
    def revoke_session(self, session_id: str, user_id: str) -> bool: ...
    def revoke_family(self, family: str) -> int: ...
    def record_login_failure(self, username: str, now: float) -> int: ...
    def get_login_failures(
        self, username: str, now: float, window_seconds: int
    ) -> int: ...
    def reset_login_failures(self, username: str) -> None: ...
    def record_refresh_abuse(self, family: str, now: float) -> int: ...
    def get_refresh_abuses(
        self, family: str, now: float, window_seconds: int
    ) -> int: ...


@dataclass
class TokenBundle:
    access_token: str
    refresh_token: str
    session: SessionRecord
