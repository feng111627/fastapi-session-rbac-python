# fastapi-session-rbac

FastAPI 会话鉴权 + 细粒度权限控制示例：登录签发访问/刷新令牌，刷新令牌可轮换并带
并发重复使用检测，多设备会话可管理可吊销，SQLite 持久化保证重启后会话与吊销状态
可恢复。仅依赖本地环境与常见开源库（FastAPI、PyJWT、SQLite），不接入任何外部服务。

## 快速开始

```bash
uv sync                 # 安装依赖
uv run python main.py   # 启动服务（默认 127.0.0.1:8000）
uv run pytest -v        # 运行测试（日志会输出各业务用例与结果）
```

内置演示账号（仅本地）：`admin/admin-pass`（admin）、`alice/alice-pass`（analyst）、
`bob/bob-pass`（viewer）。

```bash
# 登录
curl -s -X POST localhost:8000/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"alice-pass","device":"laptop"}'
# 刷新（轮换）
curl -s -X POST localhost:8000/auth/refresh \
  -H 'content-type: application/json' -d '{"refresh_token":"<refresh_token>"}'
# 访问受保护资源
curl -s localhost:8000/reports -H "Authorization: Bearer <access_token>"
```

## 令牌生命周期

```
login ──► access_token (JWT, 默认 15min) + refresh_token (不透明随机串, 默认 7d)
              │                        │
              │ 过期/吊销 → 401         │ POST /auth/refresh
              ▼                        ▼
        重新登录                 原子轮换：旧 refresh 立即作废，签发新对
```

- **访问令牌**：HS256 签名的 JWT，携带 `sub`（用户）、`sid`（会话）、`scopes`
  （由服务端角色推导，客户端无法伪造——签名不对或会话不存在都会被拒）。
- **刷新令牌**：不透明随机串，服务端只存 SHA-256 哈希；每次刷新**原子轮换**
  （单条 `UPDATE ... WHERE rotated=0` 决定唯一胜者）。
- **并发重复使用**：同一个刷新令牌被并发提交时，最多一个请求轮换成功；其余请求
  收到 `refresh_reuse_detected`，并且**整个会话家族被吊销**（视为令牌泄露），
  同时对该用户施加递进限流。因此任何时刻不存在两个都有效的新令牌。
- **登出 / 吊销**：`POST /auth/logout` 或 `POST /auth/sessions/{id}/revoke`
  立即删除该会话全部刷新令牌并标记会话吊销，访问令牌随即失效（每次请求都会
  校验会话状态）。
- **重启恢复**：用户、会话、刷新令牌哈希、吊销状态、限流计数全部存于 SQLite
  （WAL 模式），进程重启后已建立的会话与吊销状态原样恢复。

## 权限模型

角色 → 作用域的映射在服务端固定（`app/deps.py: ROLE_SCOPES`），令牌中的 scopes
只在签发时由服务端角色推导：

| 角色    | 作用域                                              |
|---------|-----------------------------------------------------|
| admin   | profile:read, reports:read, reports:write, admin:users |
| analyst | profile:read, reports:read, reports:write           |
| viewer  | profile:read, reports:read                          |

| 端点                            | 所需作用域     |
|---------------------------------|----------------|
| GET /profile, GET /auth/sessions | 登录即可 / profile:read |
| GET /reports                    | reports:read   |
| POST /reports                   | reports:write  |
| GET /admin/users                | admin:users    |

越权返回 `403 insufficient_scope`。伪造角色声明无效：自签令牌签名不合法
（`token_invalid`），用真密钥伪造会话也会因服务端无此会话而被拒
（`token_revoked`）。

## 拒绝原因（可区分）

所有鉴权失败返回 `{"error": "<reason>"}`，不泄露内部细节：

| reason                   | HTTP | 含义                           |
|--------------------------|------|--------------------------------|
| token_missing            | 401  | 未携带凭证                     |
| token_malformed          | 401  | Authorization 头格式错误       |
| token_invalid            | 401  | 签名/签发者非法或令牌不存在    |
| token_expired            | 401  | 令牌已过期                     |
| token_revoked            | 401  | 所属会话已吊销                 |
| session_revoked          | 401  | 刷新时会话已被吊销             |
| refresh_reuse_detected   | 401  | 刷新令牌重复使用（会话已吊销） |
| insufficient_scope       | 403  | 权限不足                       |
| bad_credentials          | 401  | 用户名或密码错误               |
| rate_limited             | 429  | 触发递进限流（带 Retry-After） |
| storage_unavailable      | 503  | 存储瞬时异常（已归一化）       |

## 可配置项（`app/config.py: Settings`）

| 字段 | 默认 | 说明 |
|------|------|------|
| secret_key | dev 值 | JWT HMAC 密钥，生产必须替换 |
| access_token_ttl_seconds | 900 | 访问令牌有效期 |
| refresh_token_ttl_seconds | 604800 | 刷新令牌/会话有效期 |
| db_path | auth.db | SQLite 文件路径 |
| issuer | fastapi-session-rbac | JWT iss |
| login_fail_free_attempts | 3 | 登录失败宽限次数 |
| login_fail_base/max_delay_seconds | 1 / 60 | 登录限流指数退避基数/上限 |
| login_fail_window_seconds | 600 | 失败计数衰减窗口 |
| refresh_abuse_free_attempts | 0 | 刷新异常宽限次数（0=立即限流） |
| refresh_abuse_base/max_delay_seconds | 2 / 120 | 刷新异常限流退避基数/上限 |
| refresh_abuse_window_seconds | 600 | 异常计数衰减窗口 |

## 本地验证

```bash
uv run pytest -v
```

测试覆盖（日志中可见各业务用例与结果）：

- `tests/test_refresh_rotation.py` — 令牌轮换、**并发重复使用只放行一次并吊销会话**、
  过期/未知刷新令牌
- `tests/test_rbac.py` — 三种角色的权限边界、伪造/篡改令牌、缺失/畸形/过期凭证
- `tests/test_sessions.py` — 登出立即失效、多设备定向吊销、跨用户吊销拒绝、
  **重启后会话与吊销状态恢复**
- `tests/test_ratelimit.py` — 登录失败递进锁定、成功后重置、刷新异常递进限流
- `tests/test_storage_failures.py` — 存储异常归一化为 503，不泄露底层细节
