# fastapi-session-rbac

基于 FastAPI + SQLite（仅标准库签名，无外部 JWT/鉴权服务依赖）的会话鉴权与
RBAC 权限控制示例。支持多设备会话、刷新令牌原子轮换与重用检测、主动吊销、
失败递进限制、服务重启恢复，以及对拒绝原因的可区分归一化。

## 1. 快速开始

```bash
uv sync
uv run uvicorn main:app --reload          # 启动服务（默认 127.0.0.1:8000）
# 交互式文档： http://127.0.0.1:8000/docs
```

本地演示账号（仅用于本地验证，非真实凭据）：

| 用户名 | 密码 | 角色 |
| --- | --- | --- |
| `admin` | `Admin#123` | admin, user |
| `alice` | `Alice#123` | user |
| `bob`   | `Bob#123`   | viewer |

一次完整调用：

```bash
# 1) 登录（注意设备名，用于多设备会话管理）
curl -s localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice#123","device_name":"phone"}'

# 2) 携带访问令牌访问资源
curl -s localhost:8000/me -H "Authorization: Bearer <access_token>"

# 3) 刷新（刷新令牌一次性，用后即轮换）
curl -s localhost:8000/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'

# 4) 查看 / 吊销自己的多设备会话
curl -s localhost:8000/sessions -H "Authorization: Bearer <access_token>"
curl -s localhost:8000/sessions/revoke -H "Authorization: Bearer <access_token>" \
  -H 'Content-Type: application/json' -d '{"session_id":"<sid>"}'

# 5) 登出（当前设备会话立即失效）
curl -s localhost:8000/auth/logout -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
```

## 2. 令牌生命周期

### 访问令牌（access token）

- 形态：`base64url(claims).base64url(HMAC-SHA256)`，**自包含签名令牌**，
  仅使用标准库 `hmac/hashlib` 实现。
- 声明：`iss / sub(用户ID) / sid(会话ID) / iat / exp / typ / jti`。
  **不包含任何角色或权限声明**——授权一律以请求时从数据库实时加载的
  用户角色为准，因此无法通过在令牌中伪造 `roles`/`scope` 提权。
- 默认有效期 15 分钟（`AUTH_ACCESS_TOKEN_TTL_SECONDS`）。
- 无状态签名校验之外，**每次请求都会按 `sid` 回查会话表**：会话一旦被
  登出/吊销/异常处置，即使令牌尚未过期也立即拒绝（`session_revoked`）。

### 刷新令牌（refresh token）

- 形态：32 字节随机数的 base64url，不透明、高熵；**只在签发时明文出现
  一次**，数据库仅保存其 SHA-256 哈希。
- 默认有效期 14 天（`AUTH_REFRESH_TOKEN_TTL_SECONDS`）。
- **轮换（rotation）**：每次 `/auth/refresh` 成功，旧令牌置为 `rotated`、
  新令牌置为 `active`、会话指针更新，三步在同一个 SQLite
  `BEGIN IMMEDIATE` 事务内完成。并发重复使用同一个刷新令牌时，先提交者
  成功，其余事务读到的状态已不是 `active`，因此**绝不可能同时签发出两个
  都有效的新令牌**。
- **重用检测与处置**：已经轮换过的旧令牌若被再次提交（典型的令牌失窃
  信号），服务判定为异常使用：记录该刷新族的滥用次数，并**吊销整个刷新
  令牌族**（同一会话链路上此前轮换出的新令牌也一并失效）。
- **递进限制**：刷新族在滑动窗口内的异常使用次数达到
  `AUTH_REFRESH_MAX_ABUSES`（默认 3）后，直接返回 `refresh_locked`
  （HTTP 429），窗口过后自动恢复。

### 状态判定顺序（刷新接口）

1. 令牌不存在 → `invalid_credentials`
2. 族滥用计数达阈值 → `refresh_locked`（429）
3. 会话已吊销 → `session_revoked`
4. 令牌已过期 → `token_expired`
5. 原子轮换：成功 / 旧令牌重用 → 记滥用 + 吊销族 → `refresh_token_reused`

## 3. 权限模型（RBAC）

角色与权限均在服务端维护，令牌内不承载授权信息：

| 角色 | 权限 |
| --- | --- |
| `admin` | profile:read/write, sessions:read/revoke, admin:read |
| `user`  | profile:read/write, sessions:read/revoke |
| `viewer`| profile:read, sessions:read |

| 资源 | 所需权限 |
| --- | --- |
| `GET /me` | `profile:read` |
| `POST /me/role` | `profile:write`（角色值仍受服务端白名单约束） |
| `GET /sessions` | `sessions:read` |
| `POST /sessions/revoke` | `sessions:revoke`（且只能吊销本人会话） |
| `GET /admin` | `admin:read` |

安全要点：

- **无法伪造角色**：即使持密钥自签一个带 `roles:["admin"]` 的令牌，
  授权层只读取数据库角色，普通用户访问 `/admin` 仍为 403
  （见 `tests/test_rbac.py::test_forged_role_claim_in_token_cannot_escalate`）。
- **跨用户操作被阻断**：吊销接口带 `user_id` 归属条件，吊销他人会话不生效。
- **密码存储**：PBKDF2-HMAC-SHA256（默认 200000 轮，`AUTH_PASSWORD_PBKDF2_ITERATIONS` 可调）。

## 4. 可区分的拒绝原因

所有鉴权失败均返回统一结构 `{"error": <code>, "error_description": <安全文案>}`：

| code | HTTP | 含义 |
| --- | --- | --- |
| `missing_token` | 401 | 未携带访问令牌 |
| `malformed_token` | 401 | 格式错误 / 签名无效 / 主体或会话不存在 |
| `token_expired` | 401 | 访问或刷新令牌已过期 |
| `session_revoked` | 401 | 会话已登出、被主动吊销或因异常使用被族吊销 |
| `invalid_credentials` | 401 | 用户名密码错误 / 刷新令牌无法识别 |
| `refresh_token_reused` | 401 | 已轮换的旧刷新令牌被再次使用（异常使用） |
| `login_locked` | 429 | 登录失败次数达到阈值，滑动窗口内临时锁定 |
| `refresh_locked` | 429 | 刷新族异常使用次数达到阈值 |
| `forbidden` | 403 | 已认证但角色不满足资源所需权限 |
| `storage_unavailable` | 503 | 存储/依赖瞬时故障的归一化结果，不透出底层异常 |

登录失败同样采用滑动窗口递进限制（`AUTH_LOGIN_MAX_FAILURES` /
`AUTH_LOGIN_LOCK_WINDOW_SECONDS`），成功登录会清零计数；计数按用户名隔离。
存储层抛出的底层异常被捕获并归一化为 `storage_unavailable`，响应中不会
包含 SQL、堆栈或内部路径。

## 5. 多设备会话与重启恢复

- 每次登录创建一条新会话与新的刷新令牌族；`GET /sessions` 可查看本人
  全部设备，`POST /sessions/revoke` 可吊销指定设备。
- 会话、刷新令牌谱系、吊销状态、登录失败计数、刷新滥用计数均持久化在
  SQLite 中（默认 `./data/auth.db`）。进程重启后自动建表（已存在则跳过），
  既有会话与吊销状态直接恢复，访问令牌在其有效期内跨重启继续可用。

## 6. 配置项（均可用 `AUTH_` 前缀环境变量覆盖）

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AUTH_DATABASE_URL` | `sqlite:///./data/auth.db` | SQLite 文件位置 |
| `AUTH_SECRET_KEY` | 仅开发用的内置值 | 访问令牌 HMAC 密钥，生产必须覆盖 |
| `AUTH_ACCESS_TOKEN_TTL_SECONDS` | `900` | 访问令牌有效期 |
| `AUTH_REFRESH_TOKEN_TTL_SECONDS` | `1209600` | 刷新令牌有效期（14 天） |
| `AUTH_ISSUER` | `fastapi-session-rbac` | 令牌签发方标识 |
| `AUTH_LOGIN_MAX_FAILURES` | `5` | 窗口内最大登录失败次数 |
| `AUTH_LOGIN_LOCK_WINDOW_SECONDS` | `900` | 登录失败计数窗口 |
| `AUTH_REFRESH_MAX_ABUSES` | `3` | 窗口内刷新令牌最大异常使用次数 |
| `AUTH_REFRESH_LOCK_WINDOW_SECONDS` | `1800` | 刷新滥用计数窗口 |
| `AUTH_PASSWORD_PBKDF2_ITERATIONS` | `200000` | 密码哈希迭代轮数 |

## 7. 本地验证（测试）

```bash
uv run pytest                 # 全量用例
uv run pytest -q              # 静默模式
uv run pytest -k 并发         # 只跑并发重复使用相关用例
```

测试结束时会打印“业务覆盖与用例结果”汇总，按业务分组展示每个用例及
PASS/FAIL 结果。覆盖的业务：

- **刷新令牌轮换 / 并发重复使用**：10/12 线程屏障并发重放同一刷新令牌，
  断言恰好 1 次成功、无两个并存的有效新令牌，其余以可区分原因被拒；
- **权限边界**：admin/user/viewer 对不同资源的允许与拒绝、读写分离、
  伪造 `roles` 声明无法提权、伪造签名/主体被拒；
- **吊销后失效**：登出与跨设备吊销后访问/刷新入口立即失效、越权吊销
  他人会话不生效、异常使用触发整族吊销；
- **重启恢复**：关闭并重新创建应用实例复用同一数据库，会话存活、吊销
  状态保持、多设备状态与登录锁定计数恢复；
- **递进限制与异常归一化**：登录失败窗口锁定/恢复/清零/隔离，刷新滥用
  阈值锁定/窗口恢复，存储瞬时故障归一化为 503 且不泄露内部细节。

## 8. 目录结构

```
app/
  config.py        # 配置（环境变量覆盖）
  errors.py        # 归一化错误码与 AuthError
  security.py      # PBKDF2、令牌哈希、HMAC 访问令牌签发/校验
  database.py      # SQLite 仓储（原子轮换事务、谱系表、计数窗口）
  models.py        # 领域模型与仓储协议
  rbac.py          # 角色/权限矩阵
  auth_service.py  # 登录、刷新轮换、重用处置、吊销、递进限制
  schemas.py       # HTTP 请求/响应模型
  deps.py          # Bearer 解析、主体加载、require_permission 依赖
  routes.py        # HTTP 路由
  app.py           # 应用工厂（生命周期、建表、播种、统一错误处理）
tests/             # 按业务组织的测试与覆盖日志钩子
main.py            # uvicorn 入口
```
