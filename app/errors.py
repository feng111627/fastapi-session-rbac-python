"""归一化错误码与异常类型。

所有拒绝原因使用稳定的字符串 code，调用方可以据此区分
缺失/过期/吊销/越权/异常使用/存储故障等场景。
"""

from __future__ import annotations

# 认证类（HTTP 401）
ERR_INVALID_CREDENTIALS = "invalid_credentials"
ERR_MISSING_TOKEN = "missing_token"
ERR_MALFORMED_TOKEN = "malformed_token"
ERR_TOKEN_EXPIRED = "token_expired"
ERR_SESSION_REVOKED = "session_revoked"
ERR_REFRESH_REUSED = "refresh_token_reused"
ERR_REFRESH_LOCKED = "refresh_locked"
ERR_LOGIN_LOCKED = "login_locked"
ERR_FORCE_LOGOUT_FAMILY = "family_compromised"

# 授权类（HTTP 403）
ERR_FORBIDDEN = "forbidden"

# 存储/依赖故障（HTTP 503）
ERR_STORAGE_UNAVAILABLE = "storage_unavailable"


class AuthError(Exception):
    """业务归一化异常：只透出 code 与安全的提示文案。"""

    def __init__(self, code: str, message: str, *, status_code: int = 401):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
