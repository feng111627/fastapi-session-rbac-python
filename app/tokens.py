"""Access token (signed JWT) and refresh token (opaque) primitives."""
from __future__ import annotations

import hashlib
import secrets
import time

import jwt

from app.config import Settings
from app.errors import AuthError, Reason


def issue_access_token(
    settings: Settings,
    *,
    subject: str,
    session_id: str,
    scopes: list[str],
    now: float | None = None,
) -> str:
    now = time.time() if now is None else now
    payload = {
        "iss": settings.issuer,
        "sub": subject,
        "sid": session_id,
        "jti": secrets.token_hex(8),
        "iat": int(now),
        "exp": int(now + settings.access_token_ttl_seconds),
        "scopes": sorted(scopes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_access_token(settings: Settings, token: str) -> dict:
    """Decode and verify; raises AuthError with a distinguishable reason."""
    try:
        return jwt.decode(
            token, settings.secret_key, algorithms=["HS256"], issuer=settings.issuer,
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError(Reason.TOKEN_EXPIRED) from exc
    except jwt.InvalidTokenError as exc:
        # bad signature / forged claims / wrong issuer all land here
        raise AuthError(Reason.TOKEN_INVALID) from exc


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    """Only hashes are persisted, so a DB leak does not leak usable tokens."""
    return hashlib.sha256(token.encode()).hexdigest()
