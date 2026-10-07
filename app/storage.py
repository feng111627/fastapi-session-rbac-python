"""SQLite-backed persistent store: users, sessions, refresh tokens, rate limits.

Survives restarts; all sqlite errors are normalized into StorageError so
callers never see raw driver exceptions.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import StrEnum

from app.errors import StorageError

# revoke_reason values recorded on a dead session; mapped to SessionState.
REASON_LOGOUT = "logout"
REASON_USER_REVOKE = "revoked_by_user"
REASON_LOGOUT_OTHERS = "logout_other_devices"
REASON_LOGOUT_ALL = "logout_all_devices"
REASON_REUSE = "refresh_reuse_detected"
REASON_IDLE = "idle_timeout"
REASON_ABSOLUTE = "absolute_expiry"
_REVOKED_REASONS = {
    REASON_LOGOUT, REASON_USER_REVOKE, REASON_LOGOUT_OTHERS,
    REASON_LOGOUT_ALL, REASON_REUSE,
}


class SessionState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"  # logout / explicit revoke / reuse
    EXPIRED = "expired"  # absolute lifetime cap reached
    IDLE = "idle"  # idle timeout reached


@dataclass
class SessionRecord:
    session_id: str
    username: str
    device: str
    created_at: float
    expires_at: float  # absolute deadline (created_at + max lifetime)
    revoked: bool
    revoke_reason: str | None
    last_active_at: float = 0.0
    idle_timeout: float = 1800.0
    max_lifetime: float = 7 * 24 * 3600.0
    revoked_at: float | None = None

    @property
    def state(self) -> SessionState:
        if not self.revoked:
            return SessionState.ACTIVE
        if self.revoke_reason == REASON_IDLE:
            return SessionState.IDLE
        if self.revoke_reason == REASON_ABSOLUTE:
            return SessionState.EXPIRED
        return SessionState.REVOKED


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
    SESSION_IDLE = "session_idle"
    SESSION_EXPIRED = "session_expired"


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
    revoke_reason TEXT,
    last_active_at REAL NOT NULL DEFAULT 0,
    idle_timeout REAL NOT NULL DEFAULT 1800,
    max_lifetime REAL NOT NULL DEFAULT 604800,
    revoked_at REAL
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
    def init_schema(
        self,
        idle_timeout: float = 1800.0,
        max_lifetime: float = 7 * 24 * 3600.0,
    ) -> None:
        """Create tables and upgrade pre-lifecycle databases in place."""
        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            with self._lock, self._conn:
                self._conn.executescript(_SCHEMA)
                self._migrate_sessions(idle_timeout, max_lifetime)
        except sqlite3.Error as exc:
            raise StorageError("failed to initialize storage") from exc

    def _migrate_sessions(self, idle_timeout: float, max_lifetime: float) -> None:
        """Add lifecycle columns to databases created before this feature.

        Existing sessions keep working: their old ``expires_at`` stays the
        absolute deadline, and idle bookkeeping is backfilled so they are not
        instantly treated as idle on upgrade.
        """
        cols = {
            r[1] for r in self._conn.execute("PRAGMA table_info(sessions)").fetchall()
        }
        add = [
            ("last_active_at", "REAL"),
            ("idle_timeout", "REAL"),
            ("max_lifetime", "REAL"),
            ("revoked_at", "REAL"),
        ]
        for name, decl in add:
            if name not in cols:
                self._conn.execute(f"ALTER TABLE sessions ADD COLUMN {name} {decl}")
        # these UPDATEs only hit rows that existed before the upgrade; brand-new
        # tables have no rows at all, so new-created sessions are never rewritten
        self._conn.execute(
            "UPDATE sessions SET last_active_at = created_at "
            "WHERE last_active_at IS NULL OR last_active_at = 0"
        )
        self._conn.execute(
            "UPDATE sessions SET idle_timeout=? WHERE idle_timeout IS NULL",
            (idle_timeout,),
        )
        # preserve each legacy session's original absolute deadline rather than
        # applying the new default cap
        self._conn.execute(
            "UPDATE sessions SET max_lifetime = expires_at - created_at "
            "WHERE max_lifetime IS NULL OR max_lifetime = 0"
        )
        # legacy rows recorded no revocation time; give them the full retention
        # window from the upgrade moment instead of purging them immediately
        self._conn.execute(
            "UPDATE sessions SET revoked_at=? WHERE revoked=1 AND revoked_at IS NULL",
            (time.time(),),
        )

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
                    "revoked, revoke_reason, last_active_at, idle_timeout, max_lifetime, "
                    "revoked_at) VALUES(?,?,?,?,?,0,NULL,?,?,?,NULL)",
                    (rec.session_id, rec.username, rec.device, rec.created_at, rec.expires_at,
                     rec.last_active_at, rec.idle_timeout, rec.max_lifetime),
                )
        except sqlite3.Error as exc:
            raise StorageError("failed to create session") from exc

    @staticmethod
    def _SESSION_COLS(prefix: str = "") -> str:
        p = f"{prefix}." if prefix else ""
        return (
            f"{p}session_id, {p}username, {p}device, {p}created_at, {p}expires_at, "
            f"{p}revoked, {p}revoke_reason, {p}last_active_at, {p}idle_timeout, "
            f"{p}max_lifetime, {p}revoked_at"
        )

    def get_session(self, session_id: str) -> SessionRecord | None:
        try:
            with self._lock:
                row = self._db().execute(
                    f"SELECT {self._SESSION_COLS()} FROM sessions WHERE session_id=?",
                    (session_id,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError("failed to read session") from exc
        return self._to_session(row) if row else None

    def list_sessions(self, username: str) -> list[SessionRecord]:
        try:
            with self._lock:
                rows = self._db().execute(
                    f"SELECT {self._SESSION_COLS()} FROM sessions "
                    "WHERE username=? ORDER BY created_at",
                    (username,),
                ).fetchall()
        except sqlite3.Error as exc:
            raise StorageError("failed to list sessions") from exc
        return [self._to_session(r) for r in rows]

    def revoke_session(self, session_id: str, reason: str, now: float | None = None) -> None:
        """Revoke a session and delete all its refresh tokens atomically."""
        now = time.time() if now is None else now
        try:
            with self._lock, self._db() as conn:
                self._revoke_locked(conn, session_id, reason, now)
        except sqlite3.Error as exc:
            raise StorageError("failed to revoke session") from exc

    def revoke_other_sessions(
        self, username: str, keep_session_id: str, now: float | None = None,
        *, include_current: bool = False,
    ) -> int:
        """Atomically revoke the user's other (or all) sessions.

        Returns the number of sessions revoked. Runs in one transaction with
        the refresh-token deletes, so a refresh racing this call can never
        leave a usable credential behind; the current device is kept unless
        ``include_current`` is set.
        """
        now = time.time() if now is None else now
        reason = REASON_LOGOUT_ALL if include_current else REASON_LOGOUT_OTHERS
        try:
            with self._lock, self._db() as conn:
                if include_current:
                    rows = conn.execute(
                        "SELECT session_id FROM sessions WHERE username=? AND revoked=0",
                        (username,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT session_id FROM sessions "
                        "WHERE username=? AND revoked=0 AND session_id<>?",
                        (username, keep_session_id),
                    ).fetchall()
                for (sid,) in rows:
                    self._revoke_locked(conn, sid, reason, now)
                return len(rows)
        except sqlite3.Error as exc:
            raise StorageError("failed to revoke other sessions") from exc

    def expire_due_sessions(self, now: float | None = None) -> int:
        """Mark every active session whose absolute deadline or idle timeout
        has passed as dead, deleting its refresh tokens in the same tx.

        Lazy call shared by access checks, refresh and listing. Returns the
        number of sessions expired. Absolute expiry wins when both apply.
        """
        now = time.time() if now is None else now
        try:
            with self._lock, self._db() as conn:
                rows = conn.execute(
                    f"SELECT {self._SESSION_COLS('s')} FROM sessions s "
                    "WHERE s.revoked=0 AND ("
                    "s.expires_at<=? OR s.last_active_at + s.idle_timeout<=?)",
                    (now, now),
                ).fetchall()
                count = 0
                for row in rows:
                    rec = self._to_session(row)
                    reason = REASON_ABSOLUTE if rec.expires_at <= now else REASON_IDLE
                    self._revoke_locked(conn, rec.session_id, reason, now, delete_tokens=False)
                    count += 1
                return count
        except sqlite3.Error as exc:
            raise StorageError("failed to expire sessions") from exc

    def purge_dead_sessions(self, retain_seconds: float, now: float | None = None) -> int:
        """Physically delete dead sessions older than the retention window.

        Only revoked rows are eligible, so a session that is still in use can
        never be deleted; refresh tokens (already deleted at death) are removed
        in the same transaction.
        """
        now = time.time() if now is None else now
        try:
            with self._lock, self._db() as conn:
                ids = [
                    r[0] for r in conn.execute(
                        "SELECT session_id FROM sessions "
                        "WHERE revoked=1 AND revoked_at IS NOT NULL AND revoked_at<=?",
                        (now - retain_seconds,),
                    ).fetchall()
                ]
                for sid in ids:
                    conn.execute("DELETE FROM refresh_tokens WHERE session_id=?", (sid,))
                    conn.execute("DELETE FROM sessions WHERE session_id=?", (sid,))
                return len(ids)
        except sqlite3.Error as exc:
            raise StorageError("failed to purge dead sessions") from exc

    def touch_session(self, session_id: str, now: float) -> bool:
        """Record activity (sliding the idle window).

        The timestamp only moves forward, so out-of-order concurrent activity
        can never extend or shrink the window incorrectly.
        """
        try:
            with self._lock, self._db() as conn:
                cur = conn.execute(
                    "UPDATE sessions SET last_active_at=? "
                    "WHERE session_id=? AND revoked=0 AND last_active_at<?",
                    (now, session_id, now),
                )
                return cur.rowcount == 1
        except sqlite3.Error as exc:
            raise StorageError("failed to touch session") from exc

    @staticmethod
    def _revoke_locked(conn: sqlite3.Connection, session_id: str, reason: str,
                       now: float, *, delete_tokens: bool = True) -> None:
        conn.execute(
            "UPDATE sessions SET revoked=1, revoke_reason=?, revoked_at=? "
            "WHERE session_id=?",
            (reason, now, session_id),
        )
        # active kills (logout/revoke/reuse) wipe credentials at once; natural
        # deaths (idle/absolute) keep the rows so the rejection reason stays
        # distinguishable on later use -- they are unusable and purged later
        if delete_tokens:
            conn.execute("DELETE FROM refresh_tokens WHERE session_id=?", (session_id,))

    def mark_session_dead(self, session_id: str, reason: str, now: float | None = None) -> None:
        """Mark an active session idle/absolute-expired without wiping tokens."""
        now = time.time() if now is None else now
        try:
            with self._lock, self._db() as conn:
                self._revoke_locked(conn, session_id, reason, now, delete_tokens=False)
        except sqlite3.Error as exc:
            raise StorageError("failed to mark session dead") from exc

    def revoke_session_by_token(self, token_hash: str, reason: str) -> None:
        """Revoke the session owning this refresh token and delete its tokens."""
        now = time.time()
        try:
            with self._lock, self._db() as conn:
                row = conn.execute(
                    "SELECT session_id FROM refresh_tokens WHERE token_hash=?", (token_hash,),
                ).fetchone()
                if row is None:
                    return
                self._revoke_locked(conn, row[0], reason, now)
        except sqlite3.Error as exc:
            raise StorageError("failed to revoke session") from exc

    @staticmethod
    def _to_session(row: tuple) -> SessionRecord:
        return SessionRecord(
            session_id=row[0], username=row[1], device=row[2], created_at=row[3],
            expires_at=row[4], revoked=bool(row[5]), revoke_reason=row[6],
            last_active_at=row[7], idle_timeout=row[8], max_lifetime=row[9],
            revoked_at=row[10],
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
                # lifecycle is authoritative. natural deaths keep the token row
                # so the client still gets the specific reason on later use.
                if session is not None and session.revoked:
                    if session.state is SessionState.IDLE:
                        return RotateResult(RotateStatus.SESSION_IDLE, session)
                    if session.state is SessionState.EXPIRED:
                        return RotateResult(RotateStatus.SESSION_EXPIRED, session)
                    return RotateResult(RotateStatus.SESSION_REVOKED, session)
                if session is None:
                    return RotateResult(RotateStatus.SESSION_REVOKED)
                # reuse of an already rotated token: compromise, kill family
                if rotated:
                    return RotateResult(RotateStatus.ALREADY_ROTATED, session)
                # absolute lifetime cap: refreshing forever cannot extend it
                if session.expires_at <= now:
                    self._revoke_locked(conn, session_id, REASON_ABSOLUTE, now,
                                        delete_tokens=False)
                    return RotateResult(RotateStatus.SESSION_EXPIRED, session)
                # idle timeout: refresh is activity, but only if in time
                if session.last_active_at + session.idle_timeout <= now:
                    self._revoke_locked(conn, session_id, REASON_IDLE, now,
                                        delete_tokens=False)
                    return RotateResult(RotateStatus.SESSION_IDLE, session)
                if expires_at <= now:
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
                    (new_hash, session_id, min(new_expires_at, session.expires_at), now),
                )
                # successful refresh counts as activity: slide the idle window
                conn.execute(
                    "UPDATE sessions SET last_active_at=? "
                    "WHERE session_id=? AND last_active_at<?",
                    (now, session_id, now),
                )
                session.last_active_at = max(session.last_active_at, now)
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
            f"SELECT {self._SESSION_COLS()} FROM sessions WHERE session_id=?",
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
