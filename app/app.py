"""FastAPI 应用工厂：装配路由、存储、认证服务与统一错误处理。"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.auth_service import AuthService
from app.config import Settings, get_settings
from app.database import DatabaseError, SqliteStore
from app.errors import ERR_STORAGE_UNAVAILABLE, AuthError
from app.models import UserRecord
from app.routes import router
from app.security import hash_password

logger = logging.getLogger("auth_app")

# 本地演示账号（非真实凭据；生产应通过独立渠道建户）
SEED_USERS = (
    ("u_admin", "admin", "Admin#123", ["admin", "user"]),
    ("u_alice", "alice", "Alice#123", ["user"]),
    ("u_bob", "bob", "Bob#123", ["viewer"]),
)


def _seed(service: AuthService, settings: Settings) -> None:
    iterations = settings.password_pbkdf2_iterations
    service.store.seed_users(
        [
            UserRecord(
                id=uid,
                username=name,
                password_hash=hash_password(pw, iterations=iterations),
                roles=roles,
            )
            for uid, name, pw, roles in SEED_USERS
        ]
    )


def create_app(
    settings: Settings | None = None, clock=None
) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # 确保 SQLite 父目录存在（内存库或相对路径除外）
        from app.database import parse_sqlite_url

        path = parse_sqlite_url(settings.database_url)
        if path != ":memory:":
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
        store = SqliteStore(settings.database_url)
        store.init_schema()
        service = AuthService(store, settings, clock=clock)
        _seed(service, settings)
        app.state.service = service
        logger.info("认证服务已启动，数据库=%s", settings.database_url)
        try:
            yield
        finally:
            store.close()

    app = FastAPI(
        title="fastapi-session-rbac",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.exception_handler(AuthError)
    async def auth_error_handler(
        request: Request, exc: AuthError
    ) -> JSONResponse:
        # 服务端记录完整上下文，响应只返回稳定 code 与安全文案
        logger.warning(
            "拒绝访问 path=%s code=%s detail=%s",
            request.url.path,
            exc.code,
            exc.message,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.code,
                "error_description": exc.message,
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(DatabaseError)
    async def db_error_handler(
        request: Request, exc: DatabaseError
    ) -> JSONResponse:
        logger.exception("存储异常 path=%s", request.url.path)
        return JSONResponse(
            status_code=503,
            content={
                "error": ERR_STORAGE_UNAVAILABLE,
                "error_description": "服务暂时不可用，请稍后重试",
            },
        )

    app.include_router(router)
    return app
