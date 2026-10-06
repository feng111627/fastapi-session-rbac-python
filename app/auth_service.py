"""认证服务：登录、刷新轮换、吊销、失败与滥用递进限制。

拒绝原因全部归一化为 AuthError.code：
invalid_credentials / login_locked / token_expired /
session_revoked / refresh_token_reused / refresh_locked。
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any

from app.errors import (
    ERR_INVALID_CREDENTIALS,
    ERR_LOGIN_LOCKED,
    ERR_REFRESH_LOCKED,
    ERR_REFRESH_REUSED,
    ERR_SESSION_REVOKED,
    ERR_TOKEN_EXPIRED,
    AuthError,
)
from app.models import SessionRecord, TokenBundle, UserRecord
from app.security import (
    generate_refresh_token,
    hash_password,
    issue_access_token,
    sha256_hex,
    verify_password,
)


class AuthService:
    def __init__(
        self,
        store: Any,
        settings: Any,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.store = store
        self.settings = settings
        self._clock = clock or time.time

    def _now(self) -> float:
        return self._clock()

    # ------------------------------------------------------------------
    # 令牌签发
    # ------------------------------------------------------------------
    def _issue_tokens(
        self, user: UserRecord, session: SessionRecord
    ) -> tuple[str, str]:
        access = issue_access_token(
            user.id,
            session.id,
            self.settings.secret_key,
            ttl_seconds=self.settings.access_token_ttl_seconds,
            issuer=self.settings.issuer,
            now=self._now(),
        )
        refresh = generate_refresh_token()
        session.refresh_token_hash = sha256_hex(refresh)
        return access, refresh

    def _open_session(
        self, user: UserRecord, device_name: str
    ) -> tuple[SessionRecord, str, str]:
        now = self._now()
        refresh = generate_refresh_token()
        session = SessionRecord(
            id=uuid.uuid4().hex,
            user_id=user.id,
            device_name=device_name,
            refresh_family=uuid.uuid4().hex,
            refresh_token_hash=sha256_hex(refresh),
            refresh_expires_at=now
            + self.settings.refresh_token_ttl_seconds,
            revoked=False,
            created_at=now,
            last_rotated_at=now,
        )
        self.store.create_session(session)
        access = issue_access_token(
            user.id,
            session.id,
            self.settings.secret_key,
            ttl_seconds=self.settings.access_token_ttl_seconds,
            issuer=self.settings.issuer,
            now=now,
        )
        return session, access, refresh

    # ------------------------------------------------------------------
    # 登录
    # ------------------------------------------------------------------
    def login(
        self, username: str, password: str, device_name: str
    ) -> TokenBundle:
        now = self._now()
        window = self.settings.login_lock_window_seconds
        failures = self.store.get_login_failures(username, now, window)
        if failures >= self.settings.login_max_failures:
            raise AuthError(
                ERR_LOGIN_LOCKED,
                "失败次数过多，账号已临时锁定，请稍后再试",
                status_code=429,
            )

        user = self.store.get_user_by_username(username)
        # 无论用户是否存在都执行一次校验，避免通过响应差异探测用户名
        if user is None:
            verify_password(
                password,
                hash_password(
                    "!invalid-user-placeholder!",
                    iterations=self.settings.password_pbkdf2_iterations,
                ),
            )
            count = self.store.record_login_failure(username, now)
            if count >= self.settings.login_max_failures:
                raise AuthError(
                    ERR_LOGIN_LOCKED,
                    "失败次数过多，账号已临时锁定，请稍后再试",
                    status_code=429,
                )
            raise AuthError(
                ERR_INVALID_CREDENTIALS, "用户名或密码错误", status_code=401
            )

        if not verify_password(password, user.password_hash):
            count = self.store.record_login_failure(username, now)
            if count >= self.settings.login_max_failures:
                raise AuthError(
                    ERR_LOGIN_LOCKED,
                    "失败次数过多，账号已临时锁定，请稍后再试",
                    status_code=429,
                )
            raise AuthError(
                ERR_INVALID_CREDENTIALS, "用户名或密码错误", status_code=401
            )

        # 成功：清空失败计数并建立多设备会话
        self.store.reset_login_failures(username)
        session, access, refresh = self._open_session(user, device_name)
        return TokenBundle(
            access_token=access, refresh_token=refresh, session=session
        )

    # ------------------------------------------------------------------
    # 刷新（原子轮换 + 重用检测 + 递进限制）
    # ------------------------------------------------------------------
    def refresh(self, refresh_token: str) -> TokenBundle:
        if not refresh_token:
            raise AuthError(
                ERR_INVALID_CREDENTIALS, "刷新令牌缺失", status_code=401
            )
        now = self._now()
        token_hash = sha256_hex(refresh_token)
        session = self.store.find_session_by_refresh_hash(token_hash)
        if session is None:
            raise AuthError(
                ERR_INVALID_CREDENTIALS, "刷新令牌无效", status_code=401
            )

        # 递进限制：窗口内异常使用次数过多 -> 直接锁定该族
        abuses = self.store.get_refresh_abuses(
            session.refresh_family,
            now,
            self.settings.refresh_lock_window_seconds,
        )
        if abuses >= self.settings.refresh_max_abuses:
            raise AuthError(
                ERR_REFRESH_LOCKED,
                "检测到多次令牌异常使用，会话族已被临时锁定",
                status_code=429,
            )

        # 吊销状态（登出/管理员吊销/异常使用处置后）优先判定
        if session.revoked:
            raise AuthError(
                ERR_SESSION_REVOKED, "会话已被吊销", status_code=401
            )

        if session.refresh_expires_at <= now:
            raise AuthError(
                ERR_TOKEN_EXPIRED, "刷新令牌已过期，请重新登录", status_code=401
            )

        # 先生成新明文令牌（只出现一次），再以其哈希参与原子轮换
        new_refresh = generate_refresh_token()
        status, updated = self.store.rotate_refresh(
            token_hash,
            sha256_hex(new_refresh),
            now + self.settings.refresh_token_ttl_seconds,
            now,
        )
        if status == "rotated" and updated is not None:
            access = issue_access_token(
                updated.user_id,
                updated.id,
                self.settings.secret_key,
                ttl_seconds=self.settings.access_token_ttl_seconds,
                issuer=self.settings.issuer,
                now=now,
            )
            return TokenBundle(
                access_token=access,
                refresh_token=new_refresh,
                session=updated,
            )

        if status == "reused":
            return self._handle_reuse(session, now)

        raise AuthError(
            ERR_INVALID_CREDENTIALS, "刷新令牌无效", status_code=401
        )

    def _handle_reuse(
        self, session: SessionRecord, now: float
    ) -> TokenBundle:
        """旧刷新令牌被再次提交：记录滥用并吊销整个令牌族。"""
        count = self.store.record_refresh_abuse(
            session.refresh_family, now
        )
        self.store.revoke_family(session.refresh_family)
        if count >= self.settings.refresh_max_abuses:
            raise AuthError(
                ERR_REFRESH_LOCKED,
                "检测到多次令牌异常使用，会话族已被临时锁定",
                status_code=429,
            )
        raise AuthError(
            ERR_REFRESH_REUSED,
            "刷新令牌已被使用过，相关会话已按异常使用全部吊销",
            status_code=401,
        )

    # ------------------------------------------------------------------
    # 登出 / 会话管理
    # ------------------------------------------------------------------
    def logout(self, refresh_token: str) -> None:
        if not refresh_token:
            return
        token_hash = sha256_hex(refresh_token)
        session = self.store.find_session_by_refresh_hash(token_hash)
        if session is not None and not session.revoked:
            self.store.revoke_session(session.id, session.user_id)

    def revoke_session(self, user: UserRecord, session_id: str) -> bool:
        return self.store.revoke_session(session_id, user.id)

    def list_sessions(self, user: UserRecord) -> list[SessionRecord]:
        return self.store.list_sessions(user.id)
