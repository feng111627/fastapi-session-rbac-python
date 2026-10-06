"""FastAPI dependencies: bearer extraction + scope enforcement."""
from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Request

from app.errors import AuthError, Reason, StorageError
from app.tokens import decode_access_token

# role -> granted scopes; roles come only from the server-side user store,
# never from client-supplied claims
ROLE_SCOPES: dict[str, set[str]] = {
    "admin": {"profile:read", "reports:read", "reports:write", "admin:users"},
    "analyst": {"profile:read", "reports:read", "reports:write"},
    "viewer": {"profile:read", "reports:read"},
}


def scopes_for_roles(roles: list[str] | tuple[str, ...]) -> set[str]:
    scopes: set[str] = set()
    for role in roles:
        scopes |= ROLE_SCOPES.get(role, set())
    return scopes


def get_current_claims(request: Request) -> dict:
    """Validate the bearer token and the underlying session.

    Raises AuthError with distinguishable reasons for missing / malformed /
    expired / invalid / revoked credentials.
    """
    header = request.headers.get("authorization")
    if header is None:
        raise AuthError(Reason.TOKEN_MISSING)
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthError(Reason.TOKEN_MALFORMED)
    claims = decode_access_token(request.app.state.settings, parts[1])
    sid = claims.get("sid")
    if not isinstance(sid, str):
        raise AuthError(Reason.TOKEN_INVALID)
    try:
        session = request.app.state.store.get_session(sid)
    except StorageError as exc:
        raise AuthError(Reason.STORAGE_UNAVAILABLE, status_code=503) from exc
    if session is None or session.revoked:
        raise AuthError(Reason.TOKEN_REVOKED)
    return claims


def require_scopes(*required: str) -> Callable:
    """Dependency factory enforcing that the token carries all given scopes."""

    def checker(claims: dict = Depends(get_current_claims)) -> dict:
        granted = set(claims.get("scopes") or [])
        missing = [s for s in required if s not in granted]
        if missing:
            raise AuthError(Reason.INSUFFICIENT_SCOPE, status_code=403)
        return claims

    return checker
