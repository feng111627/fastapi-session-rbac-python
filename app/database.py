"""SQLite 会话仓储。

关键并发原语：刷新轮换在单个 ``BEGIN IMMEDIATE`` 事务内完成——
旧令牌置为 rotated、新令牌写入 active、会话指针更新，三步对
其它事务要么全部可见、要么全部不可见。并发重复使用旧令牌时，
先提交者成功，后到者读到的令牌状态已是 ``rotated``，据此判定
异常使用并由上层吊销整个令牌族。

刷新令牌落库的只有 SHA-256 哈希；明文只在签发时返回一次。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time

from app.models import SessionRecord, UserRecord


class DatabaseError(Exception):
    """底层存储异常的内部包装，由上层归一化为 storage_unavailable。"""


def parse_sqlite_url(database_url: str) -> str:
    """规范化 SQLite URL。

    - sqlite://:memory:        -> :memory:
    - sqlite:///./x.db         -> ./x.db        （相对路径）
    - sqlite:////abs/path.db   -> /abs/path.db  （绝对路径，四个斜杠）
    """
    prefix = "sqlite://"
    if not database_url.startswith(prefix):
        raise DatabaseError(f"不支持的数据库 URL: {database_url!r}")
    rest = database_url[len(prefix):]
    if rest == ":memory:" or rest == "/:memory:":
        return ":memory:"
    # 相对路径形如 ///./dir/db.db：去掉恰好一个前导斜杠
    if rest.startswith("/.") or rest.startswith("/~"):
        return rest[1:]
    # 绝对路径形如 ////abs/path.db（四斜杠）或 ///abs/path.db（三斜杠）
    if rest.startswith("/"):
        return "/" + rest.lstrip("/")
    return rest


class SqliteStore:
    def __init__(self, database_url: str) -> None:
        self._path = parse_sqlite_url(database_url)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # 连接与建表
    # ------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        try:
            conn = sqlite3.connect(
                self._path, check_same_thread=False, timeout=30.0
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc
        self._conn = conn
        return conn

    def init_schema(self) -> None:
        try:
            with self._lock, self._connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        roles TEXT NOT NULL DEFAULT '[]'
                    );
                    CREATE TABLE IF NOT EXISTS sessions (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        device_name TEXT NOT NULL,
                        refresh_family TEXT NOT NULL,
                        refresh_token_hash TEXT NOT NULL UNIQUE,
                        refresh_expires_at REAL NOT NULL,
                        revoked INTEGER NOT NULL DEFAULT 0,
                        created_at REAL NOT NULL,
                        last_rotated_at REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_sessions_user
                        ON sessions(user_id);
                    CREATE INDEX IF NOT EXISTS idx_sessions_family
                        ON sessions(refresh_family);
                    CREATE TABLE IF NOT EXISTS refresh_tokens (
                        token_hash TEXT PRIMARY KEY,
                        family TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        status TEXT NOT NULL CHECK (status IN
                            ('active','rotated','revoked')),
                        created_at REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_rt_family
                        ON refresh_tokens(family);
                    CREATE TABLE IF NOT EXISTS login_failures (
                        username TEXT PRIMARY KEY,
                        failures INTEGER NOT NULL,
                        first_at REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS refresh_abuses (
                        family TEXT PRIMARY KEY,
                        abuses INTEGER NOT NULL,
                        first_at REAL NOT NULL
                    );
                    """
                )
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # ------------------------------------------------------------------
    # 行映射
    # ------------------------------------------------------------------
    @staticmethod
    def _user_from_row(row: sqlite3.Row) -> UserRecord:
        return UserRecord(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            roles=json.loads(row["roles"]),
        )

    @staticmethod
    def _session_from_row(row: sqlite3.Row) -> SessionRecord:
        return SessionRecord(
            id=row["id"],
            user_id=row["user_id"],
            device_name=row["device_name"],
            refresh_family=row["refresh_family"],
            refresh_token_hash=row["refresh_token_hash"],
            refresh_expires_at=float(row["refresh_expires_at"]),
            revoked=bool(row["revoked"]),
            created_at=float(row["created_at"]),
            last_rotated_at=float(row["last_rotated_at"]),
        )

    # ------------------------------------------------------------------
    # 用户
    # ------------------------------------------------------------------
    def create_user(self, user: UserRecord) -> None:
        try:
            with self._lock, self._connect() as conn:
                conn.execute(
                    "INSERT INTO users(id, username, password_hash, roles)"
                    " VALUES (?,?,?,?)",
                    (user.id, user.username, user.password_hash,
                     json.dumps(user.roles)),
                )
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    def seed_users(self, users: list[UserRecord]) -> None:
        for user in users:
            try:
                self.create_user(user)
            except DatabaseError:
                # 唯一键冲突视为已存在（重复播种幂等）
                existing = self.get_user_by_username(user.username)
                if existing is None:
                    raise

    def get_user_by_username(self, username: str) -> UserRecord | None:
        try:
            with self._lock, self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM users WHERE username = ?", (username,)
                ).fetchone()
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc
        return self._user_from_row(row) if row else None

    def get_user_by_id(self, user_id: str) -> UserRecord | None:
        try:
            with self._lock, self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM users WHERE id = ?", (user_id,)
                ).fetchone()
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc
        return self._user_from_row(row) if row else None

    def update_user_roles(self, user_id: str, roles: list[str]) -> None:
        try:
            with self._lock, self._connect() as conn:
                conn.execute(
                    "UPDATE users SET roles = ? WHERE id = ?",
                    (json.dumps(roles), user_id),
                )
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    # ------------------------------------------------------------------
    # 会话
    # ------------------------------------------------------------------
    def create_session(self, session: SessionRecord) -> None:
        try:
            with self._lock, self._connect() as conn:
                conn.execute(
                    "INSERT INTO sessions(id, user_id, device_name,"
                    " refresh_family, refresh_token_hash, refresh_expires_at,"
                    " revoked, created_at, last_rotated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (session.id, session.user_id, session.device_name,
                     session.refresh_family, session.refresh_token_hash,
                     session.refresh_expires_at, int(session.revoked),
                     session.created_at, session.last_rotated_at),
                )
                conn.execute(
                    "INSERT INTO refresh_tokens(token_hash, family, session_id,"
                    " expires_at, status, created_at) VALUES (?,?,?,?,?,?)",
                    (session.refresh_token_hash, session.refresh_family,
                     session.id, session.refresh_expires_at,
                     "active", session.created_at),
                )
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    def list_sessions(self, user_id: str) -> list[SessionRecord]:
        try:
            with self._lock, self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM sessions WHERE user_id = ?"
                    " ORDER BY created_at",
                    (user_id,),
                ).fetchall()
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc
        return [self._session_from_row(r) for r in rows]

    def find_session_by_refresh_hash(
        self, token_hash: str
    ) -> SessionRecord | None:
        try:
            with self._lock, self._connect() as conn:
                row = conn.execute(
                    "SELECT s.* FROM sessions s"
                    " JOIN refresh_tokens rt"
                    " ON rt.session_id = s.id"
                    " WHERE rt.token_hash = ?",
                    (token_hash,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc
        return self._session_from_row(row) if row else None

    def rotate_refresh(
        self,
        token_hash: str,
        new_hash: str,
        new_expires_at: float,
        now: float,
    ) -> tuple[str, SessionRecord | None]:
        """原子轮换。

        返回 (status, session)：
        - ``"rotated"``：本次轮换成功，session 为更新后的会话；
        - ``"reused"``：令牌已被轮换过（异常重用），session 为关联会话；
        - ``"unknown"``：令牌不存在。

        调用方负责过期与吊销判定（本方法只做状态机迁移）。
        """
        try:
            with self._lock, self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                rt = conn.execute(
                    "SELECT * FROM refresh_tokens WHERE token_hash = ?",
                    (token_hash,),
                ).fetchone()
                if rt is None:
                    conn.commit()
                    return "unknown", None
                session_row = conn.execute(
                    "SELECT * FROM sessions WHERE id = ?",
                    (rt["session_id"],),
                ).fetchone()
                if rt["status"] == "rotated" or rt["status"] == "revoked":
                    conn.commit()
                    return "reused", self._session_from_row(session_row)
                # 条件更新：仅当仍是 active 才迁移，杜绝双花
                cur = conn.execute(
                    "UPDATE refresh_tokens SET status = 'rotated'"
                    " WHERE token_hash = ? AND status = 'active'",
                    (token_hash,),
                )
                if cur.rowcount != 1:  # pragma: no cover - 由事务隔离保证
                    conn.rollback()
                    return "unknown", None
                conn.execute(
                    "UPDATE sessions SET refresh_token_hash = ?,"
                    " refresh_expires_at = ?, last_rotated_at = ?"
                    " WHERE id = ?",
                    (new_hash, new_expires_at, now, rt["session_id"]),
                )
                conn.execute(
                    "INSERT INTO refresh_tokens(token_hash, family, session_id,"
                    " expires_at, status, created_at) VALUES (?,?,?,?,?,?)",
                    (new_hash, rt["family"], rt["session_id"],
                     new_expires_at, "active", now),
                )
                conn.commit()
                row = conn.execute(
                    "SELECT * FROM sessions WHERE id = ?", (rt["session_id"],)
                ).fetchone()
                return "rotated", self._session_from_row(row)
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    def revoke_session(self, session_id: str, user_id: str) -> bool:
        """吊销单个会话；仅属主可吊销。返回是否实际生效。"""
        try:
            with self._lock, self._connect() as conn:
                cur = conn.execute(
                    "UPDATE sessions SET revoked = 1"
                    " WHERE id = ? AND user_id = ? AND revoked = 0",
                    (session_id, user_id),
                )
                conn.execute(
                    "UPDATE refresh_tokens SET status = 'revoked'"
                    " WHERE session_id = ? AND status = 'active'",
                    (session_id,),
                )
                return cur.rowcount == 1
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    def revoke_family(self, family: str) -> int:
        """吊销整个刷新令牌族（异常使用处置），返回受影响会话数。"""
        try:
            with self._lock, self._connect() as conn:
                cur = conn.execute(
                    "UPDATE sessions SET revoked = 1"
                    " WHERE refresh_family = ? AND revoked = 0",
                    (family,),
                )
                conn.execute(
                    "UPDATE refresh_tokens SET status = 'revoked'"
                    " WHERE family = ? AND status IN ('active','rotated')",
                    (family,),
                )
                return cur.rowcount
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    # ------------------------------------------------------------------
    # 登录失败计数（滑动窗口）
    # ------------------------------------------------------------------
    def record_login_failure(self, username: str, now: float) -> int:
        try:
            with self._lock, self._connect() as conn:
                row = conn.execute(
                    "SELECT failures, first_at FROM login_failures"
                    " WHERE username = ?",
                    (username,),
                ).fetchone()
                if row is None:
                    failures, first_at = 1, now
                else:
                    first_at = float(row["first_at"])
                    failures = int(row["failures"]) + 1
                conn.execute(
                    "INSERT INTO login_failures(username, failures, first_at)"
                    " VALUES (?,?,?)"
                    " ON CONFLICT(username) DO UPDATE SET"
                    " failures = excluded.failures, first_at = excluded.first_at",
                    (username, failures, first_at),
                )
                return failures
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    def get_login_failures(
        self, username: str, now: float, window_seconds: int
    ) -> int:
        try:
            with self._lock, self._connect() as conn:
                row = conn.execute(
                    "SELECT failures, first_at FROM login_failures"
                    " WHERE username = ?",
                    (username,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc
        if row is None:
            return 0
        if now - float(row["first_at"]) > window_seconds:
            return 0
        return int(row["failures"])

    def reset_login_failures(self, username: str) -> None:
        try:
            with self._lock, self._connect() as conn:
                conn.execute(
                    "DELETE FROM login_failures WHERE username = ?",
                    (username,),
                )
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    # ------------------------------------------------------------------
    # 刷新异常使用计数（滑动窗口，递进限制）
    # ------------------------------------------------------------------
    def record_refresh_abuse(self, family: str, now: float) -> int:
        try:
            with self._lock, self._connect() as conn:
                row = conn.execute(
                    "SELECT abuses, first_at FROM refresh_abuses"
                    " WHERE family = ?",
                    (family,),
                ).fetchone()
                abuses = 1 if row is None else int(row["abuses"]) + 1
                first_at = now if row is None else float(row["first_at"])
                conn.execute(
                    "INSERT INTO refresh_abuses(family, abuses, first_at)"
                    " VALUES (?,?,?)"
                    " ON CONFLICT(family) DO UPDATE SET"
                    " abuses = excluded.abuses, first_at = excluded.first_at",
                    (family, abuses, first_at),
                )
                return abuses
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc

    def get_refresh_abuses(
        self, family: str, now: float, window_seconds: int
    ) -> int:
        try:
            with self._lock, self._connect() as conn:
                row = conn.execute(
                    "SELECT abuses, first_at FROM refresh_abuses"
                    " WHERE family = ?",
                    (family,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise DatabaseError(str(exc)) from exc
        if row is None:
            return 0
        if now - float(row["first_at"]) > window_seconds:
            return 0
        return int(row["abuses"])
