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
# 查看会话（含最近活跃与 active/revoked/idle/expired 状态）
curl -s localhost:8000/auth/sessions -H "Authorization: Bearer <access_token>"
# 一键退出本账号其他设备（all_devices=true 则连当前设备一起退出）
curl -s -X POST localhost:8000/auth/sessions/logout-others \
  -H 'content-type: application/json' -H "Authorization: Bearer <access_token>" \
  -d '{"all_devices": false}'
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

## 会话生命周期（空闲失效 + 最长存活上限）

每个会话记录 `created_at`（建立时刻）、`last_active_at`（最近活跃）、
`idle_timeout` 与 `max_lifetime`（建立时按当时配置固化），并对外暴露状态：
`active / revoked / expired / idle`。

- **空闲失效（滑动）**：距最近一次使用超过 `session_idle_timeout_seconds`
  （默认 **30 分钟**）即自动失效，访问与刷新都被拒并返回 `session_idle`。
  访问受保护资源**以及刷新成功**都算一次活跃，会把空闲倒计时顺延；活跃时间
  只单调向前更新，避免乱序并发把窗口改坏。
- **最长存活上限（绝对）**：无论期间怎么刷新，会话都不能活过
  `session_max_lifetime_seconds`（默认 **7 天**，从建立时刻算起）。到点即失效，
  访问/刷新返回 `session_expired`；轮换出的刷新令牌有效期也被截断在该上限内，
  因此“一直刷新续命”不可能突破上限。
- **原因可区分**：`session_idle`（空闲太久）、`session_expired`（达到最长上限）、
  `token_revoked`/`session_revoked`（主动登出或被吊销）、`refresh_reuse_detected`
  （重用被吊销）、`token_expired`（凭证自身到期）、`token_invalid`（凭证不合法）
  各自独立，前端可分别处理。自然失效（空闲/到期）会保留凭证行以便后续请求仍能
  返回准确原因，但该凭证凭会话终态必然不可用，并在保留期后被清理。
- **失效后的清理**：列会话、登录等时机会做懒维护——把已到点的会话标记为
  `idle/expired`，并把死亡超过 `dead_session_retain_seconds`（默认 **7 天**）的
  会话连同凭证**物理删除**。清理只针对 `revoked=1` 的行并在同一事务内删除其令牌，
  因此绝不会删掉仍在正常使用或刚刷新过的会话。

## 一键退出其他设备

`POST /auth/sessions/logout-others`（用当前设备的访问令牌调用）：

```jsonc
{ "all_devices": false }   // 默认：清掉本账号下“其他”设备，保留当前设备
{ "all_devices": true }    // 连当前设备一起清掉
```

返回 `{"revoked": N}`。被清设备**立即**不可用（访问/刷新均被拒）。批量吊销与
刷新在存储层共享同一把锁、各自在单个事务内完成“标记吊销 + 删除全部刷新令牌”：
并发刷新即使先赢一步拿到新凭证，随后的批量吊销也会在同一账号范围内把它删除，
结果确定——**清完之后不存在任何仍可用的新凭证**；当前设备（除非显式
`all_devices`）与其他账号都不会被误伤。


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
| token_revoked            | 401  | 所属会话已登出/被吊销         |
| session_revoked          | 401  | 刷新时会话已被吊销             |
| session_idle             | 401  | 会话空闲太久已自动失效         |
| session_expired          | 401  | 会话达到最长存活上限           |
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
| refresh_token_ttl_seconds | 604800 | 刷新令牌有效期（会被会话绝对上限截断） |
| session_idle_timeout_seconds | 1800 | 会话空闲多久后自动失效（滑动） |
| session_max_lifetime_seconds | 604800 | 会话最长存活上限（自建立起，绝对） |
| dead_session_retain_seconds | 604800 | 已死亡会话保留多久后物理清理 |
| db_path | auth.db | SQLite 文件路径 |
| issuer | fastapi-session-rbac | JWT iss |
| login_fail_free_attempts | 3 | 登录失败宽限次数 |
| login_fail_base/max_delay_seconds | 1 / 60 | 登录限流指数退避基数/上限 |
| login_fail_window_seconds | 600 | 失败计数衰减窗口 |
| refresh_abuse_free_attempts | 0 | 刷新异常宽限次数（0=立即限流） |
| refresh_abuse_base/max_delay_seconds | 2 / 120 | 刷新异常限流退避基数/上限 |
| refresh_abuse_window_seconds | 600 | 异常计数衰减窗口 |

## 重启恢复与升级兼容

- **重启恢复**：用户、会话（含 `created_at/last_active_at/idle_timeout/
  max_lifetime/revoked_at`）、刷新令牌哈希、吊销状态与原因、限流计数全部存于
  SQLite（WAL 模式）。进程重启后空闲倒计时、最长存活上限、最近活跃时间与终态都
  原样恢复，不会因重启而全部丢失。
- **旧版本数据就地升级**：用旧版本（无生命周期列）创建的数据库在启动时自动
  `ALTER TABLE` 迁移，无需手工干预：
  - 既有会话继续可用；`max_lifetime` 按旧会话原有的 `expires_at - created_at`
    回填，**保留其原本的绝对到期时间**（不会被新的默认 7 天覆盖）；
  - `last_active_at` 回填为建立时间，避免升级瞬间被判为空闲；空闲阈值取新配置；
  - 升级前已吊销、但旧库未记录吊销时刻的会话，其保留窗口从升级时刻起算，不会被
    立即清掉；迁移可重复执行（再次启动为幂等空操作）。

## 本地验证

```bash
uv run pytest -v
```

测试覆盖（`-v --log-cli-level=INFO` 可看到各业务用例与逐条结果日志）：

- `tests/test_refresh_rotation.py` — 令牌轮换、**并发重复使用只放行一次并吊销会话**、
  过期/未知刷新令牌
- `tests/test_rbac.py` — 三种角色的权限边界、伪造/篡改令牌、缺失/畸形/过期凭证
- `tests/test_sessions.py` — 登出立即失效、多设备定向吊销、跨用户吊销拒绝、
  **重启后会话与吊销状态恢复**
- `tests/test_ratelimit.py` — 登录失败递进锁定、成功后重置、刷新异常递进限流
- `tests/test_storage_failures.py` — 存储异常归一化为 503，不泄露底层细节
- `tests/test_session_lifecycle.py` — **空闲失效（访问/刷新均可区分）、访问与刷新
  顺延空闲、边界存活、持续活跃仍在最长上限到点失效、刷新令牌不超绝对上限、
  列表展示最近活跃与状态、保留期后物理清理、清理不误删在用/刚刷新的会话**
- `tests/test_logout_others.py` — **退出其他设备立即生效、当前设备不误伤、
  `all_devices` 连当前设备一起清、跨账号隔离、刷新与批量吊销并发 20 轮后无任何
  幸存凭证**
- `tests/test_session_restart_upgrade.py` — **空闲/绝对上限/活跃时间重启恢复、
  旧版数据库就地升级保留原绝对上限且旧会话继续可用、旧吊销会话不被立即清理**
