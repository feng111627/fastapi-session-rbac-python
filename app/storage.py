"""SQLite-backed persistent store: users, sessions, refresh tokens, rate limits.

Survives restarts; all sqlite errors are normalized into StorageError so
callers never see raw driver exceptions.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from enum import StrEnum

from app.errors import StorageError


@dataclass
class SessionRecord:
    session_id: str
    username: str
    device: str
    created_at: float
    expires_at: float
    revoked: bool
    revoke_reason: str | None


@dataclass
class UserRecord:
    username: str
    password_hash: str
    roles: tuple[str, ...]


@dataclass
class LimitRecord:
    fail_count: int
    locked_until: float


class RotateStatus(StrEnum):
    OK = "ok"
    NOT_FOUND = "not_found"
    ALREADY_ROTATED = "already_rotated"  # reuse of an old refresh token
    EXPIRED = "expired"
    SESSION_REVOKED = "session_revoked"


@dataclass
class RotateResult:
    status: RotateStatus
    session: SessionRecord | None = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    roles TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    device TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoke_reason TEXT
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    expires_at REAL NOT NULL,
    rotated INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_session ON refresh_tokens(session_id);
CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    fail_count INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0
);
"""


class Store:
    """Thread-safe SQLite store. All writes are atomic per operation."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    # -- lifecycle ---------------------------------------------------------
    def init_schema(self) -> None:
        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            with self._lock, self._conn:
                self._conn.executescript(_SCHEMA)
        except sqlite3.Error as exc:
            raise StorageError("failed to initialize storage") from exc

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise StorageError("storage not initialized")
        return self._conn

    # -- users ---------------------------------------------------------------
    def upsert_user(self, username: str, password_hash: str, roles: list[str]) -> None:
        try:
            with self._lock, self._db() as conn:
                conn.execute(
                    "INSERT INTO users(username, password_hash, roles) VALUES(?,?,?) "
                    "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, "
                    "roles=excluded.roles",
                    (username, password_hash, json.dumps(list(roles))),
                )
        except sqlite3.Error as exc:
            raise StorageError("failed to write user") from exc

    def get_user(self, username: str) -> UserRecord | None:
        try:
            with self._lock:
                row = self._db().execute(
                    "SELECT username, password_hash, roles FROM users WHERE username=?",
                    (username,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError("failed to read user") from exc
        if row is None:
            return None
        return UserRecord(username=row[0], password_hash=row[1], roles=tuple(json.loads(row[2])))

    # -- sessions ------------------------------------------------------------
    def create_session(self, rec: SessionRecord) -> None:
        try:
            with self._lock, self._db() as conn:
                conn.execute(
                    "INSERT INTO sessions(session_id, username, device, created_at, expires_at, "
                    "revoked, revoke_reason) VALUES(?,?,?,?,?,0,NULL)",
                    (rec.session_id, rec.username, rec.device, rec.created_at, rec.expires_at),
                )
        except sqlite3.Error as exc:
            raise StorageError("failed to create session") from exc

    def get_session(self, session_id: str) -> SessionRecord | None:
        try:
            with self._lock:
                row = self._db().execute(
                    "SELECT session_id, username, device, created_at, expires_at, revoked, "
                    "revoke_reason FROM sessions WHERE session_id=?",
                    (session_id,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError("failed to read session") from exc
        return self._to_session(row) if row else None

    def list_sessions(self, username: str) -> list[SessionRecord]:
        try:
            with self._lock:
                rows = self._db().execute(
                    "SELECT session_id, username, device, created_at, expires_at, revoked, "
                    "revoke_reason FROM sessions WHERE username=? ORDER BY created_at",
                    (username,),
                ).fetchall()
        except sqlite3.Error as exc:
            raise StorageError("failed to list sessions") from exc
        return [self._to_session(r) for r in rows]

    def revoke_session(self, session_id: str, reason: str) -> None:
        """Revoke a session and delete all its refresh tokens atomically."""
        try:
            with self._lock, self._db() as conn:
                conn.execute(
                    "UPDATE sessions SET revoked=1, revoke_reason=? WHERE session_id=?",
                    (reason, session_id),
                )
                conn.execute("DELETE FROM refresh_tokens WHERE session_id=?", (session_id,))
        except sqlite3.Error as exc:
            raise StorageError("failed to revoke session") from exc

    def revoke_session_by_token(self, token_hash: str, reason: str) -> None:
        """Revoke the session owning this refresh token and delete its tokens."""
        try:
            with self._lock, self._db() as conn:
                row = conn.execute(
                    "SELECT session_id FROM refresh_tokens WHERE token_hash=?", (token_hash,),
                ).fetchone()
                if row is None:
                    return
                session_id = row[0]
                conn.execute(
                    "UPDATE sessions SET revoked=1, revoke_reason=? WHERE session_id=?",
                    (reason, session_id),
                )
                conn.execute("DELETE FROM refresh_tokens WHERE session_id=?", (session_id,))
        except sqlite3.Error as exc:
            raise StorageError("failed to revoke session") from exc

    @staticmethod
    def _to_session(row: tuple) -> SessionRecord:
        return SessionRecord(
            session_id=row[0], username=row[1], device=row[2], created_at=row[3],
            expires_at=row[4], revoked=bool(row[5]), revoke_reason=row[6],
        )

    # -- refresh tokens ------------------------------------------------------
    def store_refresh_token(self, token_hash: str, session_id: str, created_at: float,
                            expires_at: float) -> None:
        try:
            with self._lock, self._db() as conn:
                conn.execute(
                    "INSERT INTO refresh_tokens(token_hash, session_id, expires_at, rotated, "
                    "created_at) VALUES(?,?,?,0,?)",
                    (token_hash, session_id, expires_at, created_at),
                )
        except sqlite3.Error as exc:
            raise StorageError("failed to store refresh token") from exc

    def rotate_refresh_token(self, old_hash: str, new_hash: str, now: float,
                             new_expires_at: float) -> RotateResult:
        """Atomically rotate a refresh token.

        Exactly one concurrent caller can win the UPDATE on the un-rotated row;
        any other presentation of the same (already rotated) token is reported
        as ALREADY_ROTATED, i.e. token reuse.
        """
        try:
            with self._lock, self._db() as conn:
                row = conn.execute(
                    "SELECT session_id, expires_at, rotated FROM refresh_tokens "
                    "WHERE token_hash=?",
                    (old_hash,),
                ).fetchone()
                if row is None:
                    return RotateResult(RotateStatus.NOT_FOUND)
                session_id, expires_at, rotated = row
                session = self._get_session_locked(conn, session_id)
                if rotated:
                    return RotateResult(RotateStatus.ALREADY_ROTATED, session)
                if session is None or session.revoked:
                    return RotateResult(RotateStatus.SESSION_REVOKED, session)
                if expires_at <= now or (session and session.expires_at <= now):
                    return RotateResult(RotateStatus.EXPIRED, session)
                cur = conn.execute(
                    "UPDATE refresh_tokens SET rotated=1 WHERE token_hash=? AND rotated=0",
                    (old_hash,),
                )
                if cur.rowcount != 1:  # lost the race inside the same lock window
                    return RotateResult(RotateStatus.ALREADY_ROTATED, session)
                conn.execute(
                    "INSERT INTO refresh_tokens(token_hash, session_id, expires_at, rotated, "
                    "created_at) VALUES(?,?,?,0,?)",
                    (new_hash, session_id, new_expires_at, now),
                )
                return RotateResult(RotateStatus.OK, session)
        except sqlite3.Error as exc:
            raise StorageError("failed to rotate refresh token") from exc

    def delete_refresh_token(self, token_hash: str) -> None:
        try:
            with self._lock, self._db() as conn:
                conn.execute("DELETE FROM refresh_tokens WHERE token_hash=?", (token_hash,))
        except sqlite3.Error as exc:
            raise StorageError("failed to delete refresh token") from exc

    def _get_session_locked(self, conn: sqlite3.Connection, session_id: str) -> SessionRecord | None:
        row = conn.execute(
            "SELECT session_id, username, device, created_at, expires_at, revoked, "
            "revoke_reason FROM sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        return self._to_session(row) if row else None

    # -- rate limits ---------------------------------------------------------
    def get_limit(self, key: str) -> LimitRecord | None:
        try:
            with self._lock:
                row = self._db().execute(
                    "SELECT fail_count, locked_until FROM rate_limits WHERE key=?", (key,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError("failed to read rate limit") from exc
        return LimitRecord(fail_count=row[0], locked_until=row[1]) if row else None

    def set_limit(self, key: str, fail_count: int, locked_until: float) -> None:
        try:
            with self._lock, self._db() as conn:
                conn.execute(
                    "INSERT INTO rate_limits(key, fail_count, locked_until) VALUES(?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET fail_count=excluded.fail_count, "
                    "locked_until=excluded.locked_until",
                    (key, fail_count, locked_until),
                )
        except sqlite3.Error as exc:
            raise StorageError("failed to write rate limit") from exc

    def reset_limit(self, key: str) -> None:
        try:
            with self._lock, self._db() as conn:
                conn.execute("DELETE FROM rate_limits WHERE key=?", (key,))
        except sqlite3.Error as exc:
            raise StorageError("failed to reset rate limit") from exc
