"""RBAC: role-derived scopes, permission boundaries, forged-claim resistance."""
from __future__ import annotations

import logging
import time

import jwt
import pytest

from app.errors import Reason
from tests.conftest import auth_header, login

log = logging.getLogger("test.rbac")


@pytest.mark.parametrize("username,password,can_read,can_write,can_admin", [
    ("admin", "admin-pass", True, True, True),
    ("alice", "alice-pass", True, True, False),
    ("bob", "bob-pass", True, False, False),
])
def test_role_boundaries(client, username, password, can_read, can_write, can_admin):
    pair = login(client, username, password)
    headers = auth_header(pair["access_token"])

    r = client.get("/reports", headers=headers)
    assert (r.status_code == 200) == can_read
    w = client.post("/reports", headers=headers)
    assert (w.status_code == 201) == can_write
    a = client.get("/admin/users", headers=headers)
    assert (a.status_code == 200) == can_admin
    for resp, allowed in ((r, can_read), (w, can_write), (a, can_admin)):
        if not allowed:
            assert resp.status_code == 403
            assert resp.json()["error"] == Reason.INSUFFICIENT_SCOPE
    log.info("user=%s read=%s write=%s admin=%s enforced",
             username, can_read, can_write, can_admin)


def test_forged_role_claims_cannot_escalate(client, settings):
    """A self-minted token claiming admin scopes is rejected: the signature
    does not match the server secret."""
    forged = jwt.encode(
        {"iss": settings.issuer, "sub": "bob", "sid": "x" * 32, "jti": "y",
         "iat": int(time.time()), "exp": int(time.time()) + 600,
         "scopes": ["admin:users", "reports:write"]},
        "attacker-guessed-secret",
        algorithm="HS256",
    )
    resp = client.get("/admin/users", headers=auth_header(forged))
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.TOKEN_INVALID
    log.info("forged token rejected as token_invalid")


def test_tampered_valid_token_rejected(client, settings):
    """Even a token signed with the right secret but with a fabricated sid /
    escalated scopes cannot pass: the session must exist server-side."""
    pair = login(client, "bob", "bob-pass")
    forged = jwt.encode(
        {"iss": settings.issuer, "sub": "bob", "sid": "f" * 32, "jti": "z",
         "iat": int(time.time()), "exp": int(time.time()) + 600,
         "scopes": ["admin:users"]},
        settings.secret_key,
        algorithm="HS256",
    )
    resp = client.get("/admin/users", headers=auth_header(forged))
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.TOKEN_REVOKED  # no such live session
    log.info("token with fabricated session rejected as token_revoked")


def test_missing_and_malformed_credentials(client):
    assert client.get("/profile").json()["error"] == Reason.TOKEN_MISSING
    resp = client.get("/profile", headers={"Authorization": "Token abc"})
    assert resp.json()["error"] == Reason.TOKEN_MALFORMED
    resp = client.get("/profile", headers=auth_header("not-a-jwt"))
    assert resp.json()["error"] == Reason.TOKEN_INVALID
    log.info("missing/malformed/invalid credentials are distinguishable")


def test_expired_access_token(client, settings):
    settings.access_token_ttl_seconds = -1  # already expired at issuance
    pair = login(client, "alice", "alice-pass")
    resp = client.get("/profile", headers=auth_header(pair["access_token"]))
    assert resp.status_code == 401
    assert resp.json()["error"] == Reason.TOKEN_EXPIRED
    log.info("expired access token rejected with token_expired")
