"""基于角色/作用域的访问控制。

权限判断只依据数据库中的用户角色（由服务端在处理请求时实时加载），
访问令牌本身不携带任何角色/权限声明，因此客户端无法通过伪造声明
绕过权限边界。
"""

from __future__ import annotations

# 角色 -> 权限集合
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "profile:read",
        "profile:write",
        "sessions:read",
        "sessions:revoke",
        "admin:read",
    },
    "user": {
        "profile:read",
        "profile:write",
        "sessions:read",
        "sessions:revoke",
    },
    "viewer": {
        "profile:read",
        "sessions:read",
    },
}

# 资源 -> 所需权限
RESOURCE_PERMISSIONS: dict[str, str] = {
    "GET:/me": "profile:read",
    "POST:/me/role": "profile:write",
    "GET:/admin": "admin:read",
    "GET:/sessions": "sessions:read",
    "POST:/sessions/revoke": "sessions:revoke",
}


def permissions_for_roles(roles: list[str]) -> set[str]:
    """聚合多个角色的权限；未知角色不授予任何权限。"""
    granted: set[str] = set()
    for role in roles:
        granted |= ROLE_PERMISSIONS.get(role, set())
    return granted


def has_permission(roles: list[str], required: str) -> bool:
    """判断角色集合是否满足指定权限。"""
    return required in permissions_for_roles(roles)
