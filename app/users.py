"""User repository with PBKDF2 password hashing (stdlib only)."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from app.storage import Store, UserRecord

_ITERATIONS = 120_000


def hash_password(password: str, *, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _ITERATIONS)
    return f"pbkdf2${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt, expected = stored.split("$", 2)
    except ValueError:
        return False
    if scheme != "pbkdf2":
        return False
    candidate = hash_password(password, salt=salt).split("$", 2)[2]
    return hmac.compare_digest(candidate, expected)


class UserRepo:
    def __init__(self, store: Store) -> None:
        self._store = store

    def create(self, username: str, password: str, roles: list[str]) -> None:
        self._store.upsert_user(username, hash_password(password), roles)

    def get(self, username: str) -> UserRecord | None:
        return self._store.get_user(username)
