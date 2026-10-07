"""Application factory wiring everything together."""
from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.auth import AuthService
from app.config import Settings
from app.deps import get_current_claims, require_scopes
from app.errors import AuthError
from app.ratelimit import RateLimiter
from app.storage import Store
from app.users import UserRepo

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


class LoginRequest(BaseModel):
    username: str
    password: str
    device: str = "unknown"


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutOthersRequest(BaseModel):
    all_devices: bool = False


def create_app(settings: Settings | None = None, seed_users: bool = True) -> FastAPI:
    settings = settings or Settings()
    store = Store(settings.db_path)
    # migration defaults also cover sessions created before this feature
    store.init_schema(
        idle_timeout=float(settings.session_idle_timeout_seconds),
        max_lifetime=float(settings.session_max_lifetime_seconds),
    )
    users = UserRepo(store)
    limiter = RateLimiter(store, settings)
    auth = AuthService(settings, store, users, limiter)

    app = FastAPI(title="fastapi-session-rbac")
    app.state.settings = settings
    app.state.store = store
    app.state.auth = auth
    app.state.users = users
    app.state.limiter = limiter

    if seed_users:
        # local demo accounts only; no external credentials involved
        users.create("admin", "admin-pass", ["admin"])
        users.create("alice", "alice-pass", ["analyst"])
        users.create("bob", "bob-pass", ["viewer"])

    @app.exception_handler(AuthError)
    async def auth_error_handler(_: Request, exc: AuthError) -> JSONResponse:
        headers = {}
        if exc.retry_after is not None:
            headers["Retry-After"] = str(max(1, int(exc.retry_after)))
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.reason.value},
            headers=headers,
        )

    # -- auth endpoints ------------------------------------------------------
    @app.post("/auth/login", status_code=200)
    def login(body: LoginRequest) -> dict:
        pair = auth.login(body.username, body.password, body.device)
        return {"access_token": pair.access_token, "refresh_token": pair.refresh_token,
                "token_type": pair.token_type}

    @app.post("/auth/refresh", status_code=200)
    def refresh(body: RefreshRequest) -> dict:
        pair = auth.refresh(body.refresh_token)
        return {"access_token": pair.access_token, "refresh_token": pair.refresh_token,
                "token_type": pair.token_type}

    @app.post("/auth/logout", status_code=204)
    def logout(body: RefreshRequest) -> None:
        auth.logout(body.refresh_token)

    @app.get("/auth/sessions")
    def sessions(claims: dict = Depends(get_current_claims)) -> list[dict]:
        # listing also lazily expires due sessions and purges long-dead ones
        return [
            {"session_id": s.session_id, "device": s.device, "created_at": s.created_at,
             "expires_at": s.expires_at, "last_active_at": s.last_active_at,
             "idle_timeout": s.idle_timeout, "max_lifetime": s.max_lifetime,
             "revoked": s.revoked, "status": s.state.value,
             "revoke_reason": s.revoke_reason}
            for s in auth.list_sessions(claims["sub"])
        ]

    @app.post("/auth/sessions/logout-others", status_code=200)
    def logout_others(body: LogoutOthersRequest,
                      claims: dict = Depends(get_current_claims)) -> dict:
        # the bearer token's own session is the protected "current device"
        count = auth.logout_other_devices(
            claims["sub"], claims["sid"], include_current=body.all_devices,
        )
        return {"revoked": count}

    @app.post("/auth/sessions/{session_id}/revoke", status_code=204)
    def revoke(session_id: str, claims: dict = Depends(get_current_claims)) -> None:
        auth.revoke_session(claims["sub"], session_id)

    # -- protected resources ---------------------------------------------------
    @app.get("/profile")
    def profile(claims: dict = Depends(require_scopes("profile:read"))) -> dict:
        return {"username": claims["sub"], "session_id": claims["sid"]}

    @app.get("/reports")
    def read_reports(claims: dict = Depends(require_scopes("reports:read"))) -> dict:
        return {"reports": ["q1", "q2"], "by": claims["sub"]}

    @app.post("/reports", status_code=201)
    def write_report(claims: dict = Depends(require_scopes("reports:write"))) -> dict:
        return {"created": True, "by": claims["sub"]}

    @app.get("/admin/users")
    def admin_users(claims: dict = Depends(require_scopes("admin:users"))) -> dict:
        return {"users": ["admin", "alice", "bob"]}

    return app
