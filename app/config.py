"""Configurable settings for the auth service."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Settings:
    """Runtime configuration; all values have safe local defaults."""

    secret_key: str = "dev-only-insecure-secret-change-me-32b"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 7 * 24 * 3600
    db_path: str = "auth.db"
    issuer: str = "fastapi-session-rbac"
    # progressive rate limiting
    login_fail_free_attempts: int = 3
    login_fail_base_delay_seconds: float = 1.0
    login_fail_max_delay_seconds: float = 60.0
    login_fail_window_seconds: int = 600
    refresh_abuse_free_attempts: int = 0
    refresh_abuse_base_delay_seconds: float = 2.0
    refresh_abuse_max_delay_seconds: float = 120.0
    refresh_abuse_window_seconds: int = 600
