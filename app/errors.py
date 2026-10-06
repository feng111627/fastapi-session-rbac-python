"""Normalized, distinguishable failure taxonomy.

Every auth/storage failure surfaces as AuthError with a stable `reason`
code; internal/underlying exceptions are never leaked to clients.
"""
from __future__ import annotations

from enum import StrEnum


class Reason(StrEnum):
    TOKEN_MISSING = "token_missing"
    TOKEN_MALFORMED = "token_malformed"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_INVALID = "token_invalid"
    SESSION_REVOKED = "session_revoked"
    REFRESH_REUSE_DETECTED = "refresh_reuse_detected"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    BAD_CREDENTIALS = "bad_credentials"
    RATE_LIMITED = "rate_limited"
    STORAGE_UNAVAILABLE = "storage_unavailable"


class AuthError(Exception):
    """Domain error carrying a public reason code and HTTP status."""

    def __init__(self, reason: Reason, status_code: int = 401, retry_after: float | None = None):
        self.reason = reason
        self.status_code = status_code
        self.retry_after = retry_after
        super().__init__(reason.value)


class StorageError(Exception):
    """Internal wrapper for transient/underlying storage failures."""
