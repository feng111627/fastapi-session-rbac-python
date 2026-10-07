"""Auth service: login, refresh rotation with reuse detection, logout, revoke."""
from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass

from app.config import Settings
from app.deps import scopes_for_roles
from app.errors import AuthError, Reason, StorageError
from app.ratelimit import RateLimiter
from app.storage import (
    REASON_ABSOLUTE,
    REASON_IDLE,
    REASON_LOGOUT,
    REASON_USER_REVOKE,
    RotateStatus,
    SessionRecord,
    SessionState,
    Store,
)
from app.tokens import hash_refresh_token, issue_access_token, new_refresh_token
from app.users import UserRepo, verify_password

log = logging.getLogger("auth")


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


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
    ) -> None:
        self._settings = settings
        self._store = store
        self._users = users
        self._limiter = limiter

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
        now = time.time()
        old_hash = hash_refresh_token(refresh_token)
        new_token = new_refresh_token()
        try:
            result = self._store.rotate_refresh_token(
                old_hash,
                hash_refresh_token(new_token),
                now,
                now + self._settings.refresh_token_ttl_seconds,
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
        if result.status is RotateStatus.SESSION_EXPIRED:
            log.info("refresh rejected: session %s reached absolute lifetime",
                     session.session_id if session else "?")
            raise AuthError(Reason.SESSION_EXPIRED)
        if result.status is RotateStatus.SESSION_IDLE:
            log.info("refresh rejected: session %s idle too long",
                     session.session_id if session else "?")
            raise AuthError(Reason.SESSION_IDLE)
        if result.status is RotateStatus.SESSION_REVOKED:
            raise AuthError(Reason.SESSION_REVOKED)
        raise AuthError(Reason.TOKEN_INVALID)  # NOT_FOUND

    # -- logout / revoke -------------------------------------------------------
    def logout(self, refresh_token: str) -> None:
        if not refresh_token:
            raise AuthError(Reason.TOKEN_MISSING)
        try:
            self._store.revoke_session_by_token(
                hash_refresh_token(refresh_token), REASON_LOGOUT,
            )
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    def authorize_session(self, session_id: str) -> SessionRecord:
        """Validate an access request against session lifecycle state.

        Applies lazy idle/absolute expiry for this session, records the
        activity (sliding the idle window), and raises with a reason that
        distinguishes revoked / idle / absolute-expired.
        """
        now = time.time()
        try:
            session = self._store.get_session(session_id)
            if session is None:
                raise AuthError(Reason.TOKEN_REVOKED)
            if not session.revoked:
                if session.expires_at <= now:
                    self._store.mark_session_dead(session.session_id, REASON_ABSOLUTE, now)
                    raise AuthError(Reason.SESSION_EXPIRED)
                if session.last_active_at + session.idle_timeout <= now:
                    self._store.mark_session_dead(session.session_id, REASON_IDLE, now)
                    raise AuthError(Reason.SESSION_IDLE)
                # active use keeps the idle window fresh (monotonic)
                self._store.touch_session(session.session_id, now)
            else:
                if session.state is SessionState.IDLE:
                    raise AuthError(Reason.SESSION_IDLE)
                if session.state is SessionState.EXPIRED:
                    raise AuthError(Reason.SESSION_EXPIRED)
                raise AuthError(Reason.TOKEN_REVOKED)
            return session
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    def list_sessions(self, username: str) -> list[SessionRecord]:
        """Return the user's visible sessions, applying lifecycle first.

        Due idle/absolute sessions are marked dead, and dead sessions past the
        retention window are physically purged (with their credentials), so the
        active list never accumulates dead rows.
        """
        try:
            self._store.expire_due_sessions()
            self._store.purge_dead_sessions(self._settings.dead_session_retain_seconds)
            return self._store.list_sessions(username)
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    def run_session_maintenance(self) -> None:
        """Explicit lazy maintenance: expire due sessions then purge old dead."""
        try:
            self._store.expire_due_sessions()
            self._store.purge_dead_sessions(self._settings.dead_session_retain_seconds)
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    def revoke_session(self, username: str, session_id: str) -> None:
        try:
            rec = self._store.get_session(session_id)
            if rec is None or rec.username != username:
                # do not reveal existence of other users' sessions
                raise AuthError(Reason.SESSION_REVOKED, status_code=404)
            self._store.revoke_session(session_id, REASON_USER_REVOKE)
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    def logout_other_devices(
        self, username: str, current_session_id: str, *, include_current: bool = False,
    ) -> int:
        """Revoke the user's other devices (or all devices) atomically.

        The revocation and credential deletion share one transaction with any
        concurrent refresh (store-level lock), so a racing refresh either
        commits before the revoke (and is then revoked anyway) or is rejected;
        there is no outcome where a fresh credential survives the sweep.
        """
        try:
            owner = self._store.get_session(current_session_id)
            if owner is None or owner.username != username:
                raise AuthError(Reason.SESSION_REVOKED, status_code=404)
            return self._store.revoke_other_sessions(
                username, current_session_id, include_current=include_current,
            )
        except StorageError as exc:
            raise _storage_fail(exc) from exc

    # -- helpers ---------------------------------------------------------------
    def _issue_pair(self, username: str, device: str) -> TokenPair:
        now = time.time()
        s = self._settings
        absolute_end = now + s.session_max_lifetime_seconds
        session = SessionRecord(
            session_id=secrets.token_hex(16),
            username=username,
            device=device,
            created_at=now,
            expires_at=absolute_end,
            revoked=False,
            revoke_reason=None,
            last_active_at=now,
            idle_timeout=float(s.session_idle_timeout_seconds),
            max_lifetime=float(s.session_max_lifetime_seconds),
            revoked_at=None,
        )
        refresh = new_refresh_token()
        self._store.create_session(session)
        # the first refresh token cannot outlive the session itself
        self._store.store_refresh_token(
            hash_refresh_token(refresh), session.session_id, now,
            min(now + s.refresh_token_ttl_seconds, absolute_end),
        )
        log.info("session %s created for user=%s device=%s", session.session_id, username, device)
        return self._pair_for_session(session, refresh)

    def _pair_for_session(self, session: SessionRecord, refresh: str) -> TokenPair:
        user = self._users.get(session.username)
        roles = list(user.roles) if user else []
        access = issue_access_token(
            self._settings,
            subject=session.username,
            session_id=session.session_id,
            scopes=sorted(scopes_for_roles(roles)),
        )
        return TokenPair(access_token=access, refresh_token=refresh)
