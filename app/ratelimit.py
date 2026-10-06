"""Progressive (exponential-backoff) rate limiting, persisted in the store."""
from __future__ import annotations

import time

from app.config import Settings
from app.errors import AuthError, Reason
from app.storage import Store


class RateLimiter:
    """Tracks failures per key; lockout delay grows exponentially."""

    def __init__(self, store: Store, settings: Settings) -> None:
        self._store = store
        self._settings = settings

    def _check(self, key: str) -> None:
        rec = self._store.get_limit(key)
        if rec and rec.locked_until > time.time():
            raise AuthError(
                Reason.RATE_LIMITED,
                status_code=429,
                retry_after=rec.locked_until - time.time(),
            )

    def _record(self, key: str, base: float, cap: float, window: int, free: int) -> None:
        now = time.time()
        rec = self._store.get_limit(key)
        count = rec.fail_count if rec else 0
        # decay: ignore failures older than the window
        if rec and rec.locked_until and rec.locked_until + window < now:
            count = 0
        count += 1
        locked_until = now + min(cap, base * (2 ** (count - free - 1))) if count > free else 0.0
        self._store.set_limit(key, count, locked_until)

    def check_login(self, username: str) -> None:
        self._check(f"login:{username}")

    def record_login_failure(self, username: str) -> None:
        s = self._settings
        self._record(f"login:{username}", s.login_fail_base_delay_seconds,
                     s.login_fail_max_delay_seconds, s.login_fail_window_seconds,
                     s.login_fail_free_attempts)

    def reset_login(self, username: str) -> None:
        self._store.reset_limit(f"login:{username}")

    def check_refresh_abuse(self, username: str) -> None:
        self._check(f"refresh:{username}")

    def record_refresh_abuse(self, username: str) -> None:
        s = self._settings
        self._record(f"refresh:{username}", s.refresh_abuse_base_delay_seconds,
                     s.refresh_abuse_max_delay_seconds, s.refresh_abuse_window_seconds,
                     s.refresh_abuse_free_attempts)
