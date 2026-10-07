"""Auth service: login, refresh rotation with reuse detection, logout, revoke,
session lifecycle (idle timeout, absolute lifetime, bulk revoke, cleanup)."""
from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

from app.config import Settings
from app.deps import scopes_for_roles
from app.errors import AuthError, Reason, StorageError
from app.ratelimit import RateLimiter
from app.storage import RotateStatus, SessionRecord, Store, session_status
from app.tokens import hash_refresh_token, issue_access_token, new_refresh_token
from app.users import UserRepo, verify_password

log = logging.getLogger("auth")


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


@dataclass
class SessionInfo:
    """SessionRecord enriched with its derived lifecycle status.

    Unknown attributes fall through to the underlying record, so existing
    callers using `s.session_id` / `s.revoked` keep working.
    """

    record: SessionRecord
    status: str  # active / revoked / expired / idle_expired

    def __getattr__(self, name: str):
        return getattr(self.record, name)


def _storage_fail(exc: StorageError) -> AuthError:
    # normalize transient/underlying storage failures; never leak details
    log.warning("storage failure: %s", type(exc.__cause__).__name__ if exc.__cause__ else exc)
    return AuthError(Reason.STORAGE_UNAVAILABLE, status_code=503)


class AuthService:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        users: UserRepo,
        limiter: RateLimiter,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings
        self._store = store
        self._users = users
        self._limiter = limiter
        self._now = now_fn

    # -- login ---------------------------------------------------------------
    def login(self, username: str, password: str, device: str = "unknown") -> TokenPair:
        try:
            self._limiter.check_login(username)
            user = self._users.get(username)
            if user is None or not verify_password(password, user.password_hash):
                self._limiter.record_login_failure(username)
                log.info("login failed for user=%s", username)
                raise AuthError(Reason.BAD_CREDENTIALS)
            self._limiter.reset_login(username)
            return self._issue_pair(username, device)
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    # -- refresh ---------------------------------------------------------------
    def refresh(self, refresh_token: str) -> TokenPair:
        if not refresh_token:
            raise AuthError(Reason.TOKEN_MISSING)
        now = self._now()
        old_hash = hash_refresh_token(refresh_token)
        new_token = new_refresh_token()
        try:
            result = self._store.rotate_refresh_token(
                old_hash,
                hash_refresh_token(new_token),
                now,
                now + self._settings.refresh_token_ttl_seconds,
                idle_timeout=self._settings.session_idle_timeout_seconds,
            )
        except StorageError as exc:
            raise _storage_fail(exc) from exc

        session = result.session
        username = session.username if session else "unknown"

        if result.status is RotateStatus.OK:
            assert session is not None
            return self._pair_for_session(session, new_token)
        if result.status is RotateStatus.ALREADY_ROTATED:
            # reuse of a rotated refresh token: treat as compromise, kill the
            # whole session family and apply progressive limiting
            try:
                if session is not None:
                    self._store.revoke_session(session.session_id, "refresh_reuse_detected")
                self._limiter.record_refresh_abuse(username)
            except StorageError as exc:
                raise _storage_fail(exc) from exc
            log.warning("refresh token reuse detected, session=%s revoked",
                        session.session_id if session else "?")
            raise AuthError(Reason.REFRESH_REUSE_DETECTED)
        if result.status is RotateStatus.EXPIRED:
            raise AuthError(Reason.TOKEN_EXPIRED)
        if result.status is RotateStatus.IDLE_EXPIRED:
            log.info("refresh rejected: session=%s idle too long",
                     session.session_id if session else "?")
            raise AuthError(Reason.SESSION_IDLE_EXPIRED)
        if result.status is RotateStatus.SESSION_REVOKED:
            raise AuthError(Reason.SESSION_REVOKED)
        raise AuthError(Reason.TOKEN_INVALID)  # NOT_FOUND

    # -- logout / revoke -------------------------------------------------------
    def logout(self, refresh_token: str) -> None:
        if not refresh_token:
            raise AuthError(Reason.TOKEN_MISSING)
        try:
            self._store.revoke_session_by_token(hash_refresh_token(refresh_token), "logout")
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    def list_sessions(self, username: str) -> list[SessionInfo]:
        """List sessions with derived status; purges long-terminal rows first."""
        try:
            self.cleanup_expired()
            now = self._now()
            idle = self._settings.session_idle_timeout_seconds
            return [
                SessionInfo(record=rec, status=session_status(rec, now, idle))
                for rec in self._store.list_sessions(username)
            ]
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    def cleanup_expired(self) -> int:
        """Purge terminal sessions past their retention and dead token hashes."""
        try:
            purged = self._store.purge_terminal_sessions(
                self._now(),
                self._settings.session_idle_timeout_seconds,
                self._settings.terminated_session_retention_seconds,
            )
            if purged:
                log.info("purged %d terminal session(s)", purged)
            return purged
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    def revoke_session(self, username: str, session_id: str) -> None:
        try:
            rec = self._store.get_session(session_id)
            if rec is None or rec.username != username:
                # do not reveal existence of other users' sessions
                raise AuthError(Reason.SESSION_REVOKED, status_code=404)
            self._store.revoke_session(session_id, "revoked_by_user")
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    def revoke_other_sessions(self, username: str, current_session_id: str,
                              include_current: bool = False) -> int:
        """Bulk-revoke the user's sessions ("log out other devices").

        Atomic with respect to concurrent refreshes: once this returns, no
        session it caught can mint or hold a usable credential. The current
        device is spared unless include_current is set.
        """
        try:
            spared = None if include_current else current_session_id
            count = self._store.revoke_sessions_for_user(
                username, "logout_all" if include_current else "logout_others",
                except_session_id=spared,
            )
            log.info("bulk revoke user=%s revoked=%d spared=%s", username, count, spared)
            return count
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    # -- helpers ---------------------------------------------------------------
    def _issue_pair(self, username: str, device: str) -> TokenPair:
        now = self._now()
        session = SessionRecord(
            session_id=secrets.token_hex(16),
            username=username,
            device=device,
            created_at=now,
            expires_at=now + self._settings.session_max_lifetime_seconds,
            revoked=False,
            revoke_reason=None,
            last_active_at=now,
        )
        refresh = new_refresh_token()
        self._store.create_session(session)
        self._store.store_refresh_token(
            hash_refresh_token(refresh), session.session_id, now,
            now + self._settings.refresh_token_ttl_seconds,
        )
        log.info("session %s created for user=%s device=%s", session.session_id, username, device)
        return self._pair_for_session(session, refresh)

    def _pair_for_session(self, session: SessionRecord, refresh: str) -> TokenPair:
        user = self._users.get(session.username)
        roles = list(user.roles) if user else []
        # NB: JWT iat/exp must use the wall clock because PyJWT validates them
        # against it; the injected clock only drives session lifecycle state.
        access = issue_access_token(
            self._settings,
            subject=session.username,
            session_id=session.session_id,
            scopes=sorted(scopes_for_roles(roles)),
        )
        return TokenPair(access_token=access, refresh_token=refresh)
