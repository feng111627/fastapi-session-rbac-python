"""测试公共夹具与业务覆盖日志。

约定：每个测试函数的 docstring 第一行为
``【业务名称】用例描述 -> 预期结果``，
运行 pytest 时会以“业务 / 用例 / 结果”表格打印覆盖情况。
"""

from __future__ import annotations

import logging
import tempfile

import pytest
from fastapi.testclient import TestClient

from app.app import create_app
from app.config import Settings


def make_settings(**overrides) -> Settings:
    tmpdir = tempfile.mkdtemp(prefix="authdb_")
    defaults = dict(
        database_url=f"sqlite:///{tmpdir}/test.db",
        secret_key="test-secret",
        access_token_ttl_seconds=900,
        refresh_token_ttl_seconds=86400,
        password_pbkdf2_iterations=1000,
        login_max_failures=3,
        login_lock_window_seconds=900,
        refresh_max_abuses=3,
        refresh_lock_window_seconds=1800,
    )
    defaults.update(overrides)
    return Settings(**defaults)


class Clock:
    """测试可控时钟。"""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def client(settings, clock) -> TestClient:
    """装配使用临时文件库与可控时钟的 TestClient。"""
    app = create_app(settings, clock=clock)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def service(client):
    return client.app.state.service


def login(client, username: str, password: str, device: str = "dev") -> dict:
    resp = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password,
            "device_name": device,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def auth_header(token: dict | str) -> dict[str, str]:
    access = token["access_token"] if isinstance(token, dict) else token
    return {"Authorization": f"Bearer {access}"}


@pytest.fixture
def alice(client):
    return login(client, "alice", "Alice#123", "alice-phone")


# ----------------------------------------------------------------------
# 业务覆盖日志：测试结束后按业务分组打印 用例 -> 结果
# ----------------------------------------------------------------------
def _parse_doc(item) -> tuple[str, str]:
    doc = (item.function.__doc__ or "").strip().splitlines()
    head = doc[0].strip() if doc else item.name
    if head.startswith("【") and "】" in head:
        business, rest = head[1:].split("】", 1)
        return business.strip(), rest.strip()
    return "未分类", head


def pytest_configure(config):
    logging.getLogger().setLevel(logging.WARNING)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if call.when == "call" or (
        call.when == "setup" and report.failed
    ):
        business, case = _parse_doc(item)
        report.business = business  # type: ignore[attr-defined]
        report.case = case  # type: ignore[attr-defined]


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    groups: dict[str, list[tuple[str, str]]] = {}
    for reports in terminalreporter.stats.values():
        for rep in reports:
            if not getattr(rep, "when", None) == "call":
                continue
            business = getattr(rep, "business", "未分类")
            case = getattr(rep, "case", rep.nodeid)
            if rep.passed:
                result = "PASS"
            elif rep.skipped:
                result = "SKIP"
            else:
                result = "FAIL"
            groups.setdefault(business, []).append((case, result))

    if not groups:
        return
    writer = terminalreporter
    writer.line("")
    writer.write_sep("=", "业务覆盖与用例结果")
    total = passed = 0
    for business in sorted(groups):
        writer.write_line(f"■ 业务: {business}")
        for case, result in groups[business]:
            total += 1
            passed += result == "PASS"
            writer.write_line(f"    [{result}] {case}")
    writer.write_sep("=", f"合计 {passed}/{total} 用例通过")
