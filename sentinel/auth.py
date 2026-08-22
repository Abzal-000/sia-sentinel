"""
Authentication and Authorization for SIA Sentinel API.

Provides:
- API Key authentication
- JWT token generation and validation
- Role-Based Access Control (RBAC)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyHeader

# === Configuration ===

_env_jwt_secret = os.getenv("JWT_SECRET_KEY")

if _env_jwt_secret:
    JWT_SECRET_KEY = _env_jwt_secret
else:
    # Эфемерный секрет: токены не переживут рестарт. Для продакшена
    # обязателен стабильный JWT_SECRET_KEY из окружения.
    JWT_SECRET_KEY = secrets.token_hex(32)
    print(
        "WARNING: JWT_SECRET_KEY not set — generated an ephemeral secret; "
        "issued tokens will not survive restarts. Set JWT_SECRET_KEY in production."
    )

JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
BEARER_SCHEME = HTTPBearer(auto_error=False)


# === Enums and Data Classes ===

class UserRole(str, Enum):
    """User roles for RBAC."""
    ADMIN = "admin"
    VERIFIER = "verifier"
    USER = "user"
    ANONYMOUS = "anonymous"


@dataclass
class APIKey:
    """API Key for authentication."""
    key_id: str
    hashed_key: str
    name: str
    role: UserRole
    created_at: str
    expires_at: Optional[str] = None
    is_active: bool = True
    last_used: Optional[str] = None
    tenant_id: str = "default"
    # True только для ключей админа платформы (управление всеми тенантами).
    # Админ отдельного тенанта имеет role=ADMIN, но is_platform_admin=False.
    is_platform_admin: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict (without sensitive data)."""
        return {
            "key_id": self.key_id,
            "name": self.name,
            "role": self.role.value if isinstance(self.role, UserRole) else self.role,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "is_active": self.is_active,
            "last_used": self.last_used,
            "tenant_id": self.tenant_id,
            "is_platform_admin": self.is_platform_admin,
        }


@dataclass
class User:
    """Authenticated user."""
    user_id: str
    username: str
    role: UserRole
    permissions: list[str] = field(default_factory=list)
    tenant_id: str = "default"
    is_platform_admin: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role.value if isinstance(self.role, UserRole) else self.role,
            "permissions": self.permissions,
            "tenant_id": self.tenant_id,
            "is_platform_admin": self.is_platform_admin,
        }


# === API Key Manager ===

class APIKeyManager:
    """
    Manages API keys for authentication.

    In production, use a secure database and hash with bcrypt/argon2.
    """

    # Как часто last_used сбрасывается на диск: обновление метки не
    # должно переписывать файл ключей на каждый запрос (H3).
    LAST_USED_FLUSH_SECONDS = 60.0

    def __init__(self, keys_file: Optional[str] = None):
        self.keys_file = Path(keys_file or os.getenv("API_KEYS_FILE") or "api_keys.json")
        self.keys: dict[str, APIKey] = {}
        self._lock = threading.Lock()
        self._last_used_saved_at = 0.0
        self._load_keys()

    def _load_keys(self) -> None:
        """Load keys from disk."""
        if self.keys_file.exists():
            with open(self.keys_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for key_data in data.get("keys", []):
                    # Convert role string back to UserRole enum
                    if isinstance(key_data.get("role"), str):
                        key_data["role"] = UserRole(key_data["role"])
                    key_data.setdefault("tenant_id", "default")
                    key_data.setdefault("is_platform_admin", False)
                    key = APIKey(**key_data)
                    self.keys[key.key_id] = key

    def _save_keys(self) -> None:
        """Save keys to disk atomically (tmp file + rename).

        Запись идёт во временный файл в той же директории и заменяет
        целевой через os.replace, поэтому читатели никогда не видят
        обрезанный наполовину файл (H3).
        """
        data = {
            "keys": [
                {
                    "key_id": k.key_id,
                    "hashed_key": k.hashed_key,
                    "name": k.name,
                    "role": k.role.value if isinstance(k.role, UserRole) else k.role,
                    "created_at": k.created_at,
                    "expires_at": k.expires_at,
                    "is_active": k.is_active,
                    "last_used": k.last_used,
                    "tenant_id": k.tenant_id,
                    "is_platform_admin": k.is_platform_admin,
                }
                for k in self.keys.values()
            ]
        }

        self.keys_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self.keys_file.parent),
            prefix=f".{self.keys_file.name}.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, self.keys_file)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _hash_key(self, key: str) -> str:
        """Hash API key for storage."""
        return hashlib.sha256(key.encode()).hexdigest()

    def create_key(
        self,
        name: str,
        role: UserRole = UserRole.USER,
        expires_in_days: Optional[int] = None,
        tenant_id: str = "default",
        is_platform_admin: bool = False,
        key_material: Optional[str] = None,
    ) -> tuple[str, APIKey]:
        """
        Create new API key.

        Args:
            key_material: явный материал ключа (например, из env для
                bootstrap платформенного админа). На диск попадает только
                хеш, как и у сгенерированных ключей. По умолчанию
                генерируется случайно.

        Returns:
            Tuple of (plain_key, APIKey object)
        """
        if key_material is not None and not key_material.strip():
            raise ValueError("key_material must be non-empty when provided")

        key_id = secrets.token_urlsafe(16)
        plain_key = key_material if key_material is not None else secrets.token_urlsafe(32)
        hashed_key = self._hash_key(plain_key)

        created_at = datetime.now(timezone.utc).isoformat()
        expires_at = None
        if expires_in_days:
            expires_at = (
                datetime.now(timezone.utc) + timedelta(days=expires_in_days)
            ).isoformat()

        api_key = APIKey(
            key_id=key_id,
            hashed_key=hashed_key,
            name=name,
            role=role,
            created_at=created_at,
            expires_at=expires_at,
            is_active=True,
            tenant_id=tenant_id,
            is_platform_admin=is_platform_admin,
        )

        with self._lock:
            self.keys[key_id] = api_key
            self._save_keys()

        return plain_key, api_key

    def validate_key(self, plain_key: str) -> Optional[APIKey]:
        """
        Validate API key.

        Returns:
            APIKey if valid, None otherwise
        """
        hashed_key = self._hash_key(plain_key)

        for api_key in self.keys.values():
            if not hmac.compare_digest(api_key.hashed_key, hashed_key):
                continue

            # Check if active
            if not api_key.is_active:
                continue

            # Check expiration
            if api_key.expires_at:
                expires_at = datetime.fromisoformat(api_key.expires_at)
                if datetime.now(timezone.utc) > expires_at:
                    continue

            # Обновляем метку в памяти всегда, а на диск сбрасываем не
            # чаще раза в LAST_USED_FLUSH_SECONDS — запись на каждый
            # запрос создавала гонку и риск потери файла ключей (H3).
            api_key.last_used = datetime.now(timezone.utc).isoformat()
            now = time.monotonic()
            if now - self._last_used_saved_at >= self.LAST_USED_FLUSH_SECONDS:
                with self._lock:
                    self._last_used_saved_at = now
                    self._save_keys()

            return api_key

        return None

    def revoke_key(self, key_id: str) -> bool:
        """Revoke API key."""
        with self._lock:
            if key_id not in self.keys:
                return False

            self.keys[key_id].is_active = False
            self._save_keys()
        return True

    def bootstrap_platform_admin(self, key_material: str) -> Optional[APIKey]:
        """Создать платформенного админа, если его ещё нет (deploy bootstrap).

        На свежем томе платформенного админа получить нечем: signup выдаёт
        только админа тенанта, демо-логин в проде выключен — а анкоринг,
        чекпоинты, ротация ключей и управление тенантами требуют именно
        его. Ключ задаётся env-переменной PLATFORM_ADMIN_API_KEY и на диск
        попадает только хешем.

        Идемпотентно: если активный платформенный админ уже существует
        (включая созданный через API), ничего не делает и возвращает None.
        Смена env-значения требует ревока старого bootstrap-ключа через API.
        """
        if not key_material.strip():
            raise ValueError("PLATFORM_ADMIN_API_KEY must be non-empty")

        with self._lock:
            has_admin = any(
                k.is_platform_admin and k.is_active for k in self.keys.values()
            )

        if has_admin:
            return None

        _, api_key = self.create_key(
            name="platform-admin-bootstrap",
            role=UserRole.ADMIN,
            is_platform_admin=True,
            key_material=key_material,
        )
        print(
            "BOOTSTRAP: created platform admin API key 'platform-admin-bootstrap' "
            "from PLATFORM_ADMIN_API_KEY (anchoring/checkpoints/rotation/tenant "
            "management are now operable)"
        )
        return api_key

    def list_keys(self) -> list[APIKey]:
        """List all API keys."""
        return list(self.keys.values())


# === JWT Manager ===

class JWTManager:
    """
    Manages JWT tokens for user sessions.
    """

    def __init__(
        self,
        secret_key: str = JWT_SECRET_KEY,
        algorithm: str = JWT_ALGORITHM,
        expiration_hours: int = JWT_EXPIRATION_HOURS,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.expiration_hours = expiration_hours

    def create_token(
        self,
        user_id: str,
        username: str,
        role: UserRole,
        permissions: Optional[list[str]] = None,
        tenant_id: str = "default",
        is_platform_admin: bool = False,
    ) -> str:
        """
        Create JWT token.

        Args:
            user_id: User ID
            username: Username
            role: User role
            permissions: List of permissions
            tenant_id: Tenant (organization) the user belongs to
            is_platform_admin: Platform-wide admin privileges

        Returns:
            JWT token string
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=self.expiration_hours)

        payload = {
            "sub": user_id,
            "username": username,
            "role": role.value,
            "permissions": permissions or [],
            "tenant_id": tenant_id,
            "is_platform_admin": is_platform_admin,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def validate_token(self, token: str) -> Optional[User]:
        """
        Validate JWT token.

        Returns:
            User if valid, None otherwise
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
            )

            return User(
                user_id=payload["sub"],
                username=payload["username"],
                role=UserRole(payload["role"]),
                permissions=payload.get("permissions", []),
                tenant_id=payload.get("tenant_id", "default"),
                # Старые токены без claim считаются не-платформенными
                is_platform_admin=bool(payload.get("is_platform_admin", False)),
            )
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None


# === Authentication Dependencies ===

# Global instances
api_key_manager = APIKeyManager()
jwt_manager = JWTManager()


async def get_current_user(
    api_key: Optional[str] = Security(API_KEY_HEADER),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(BEARER_SCHEME),
) -> User:
    """
    Get current authenticated user.

    Supports both API Key and JWT Bearer authentication.
    """
    # Try API Key first
    if api_key:
        key_obj = api_key_manager.validate_key(api_key)
        if key_obj:
            return User(
                user_id=key_obj.key_id,
                username=key_obj.name,
                role=key_obj.role,
                permissions=[],
                tenant_id=key_obj.tenant_id,
                is_platform_admin=key_obj.is_platform_admin,
            )

    # Try JWT Bearer
    if bearer:
        user = jwt_manager.validate_token(bearer.credentials)
        if user:
            return user

    # No valid authentication
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_optional_user(
    api_key: Optional[str] = Security(API_KEY_HEADER),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(BEARER_SCHEME),
) -> User:
    """
    Get current user if authenticated, otherwise return anonymous.
    """
    try:
        return await get_current_user(api_key, bearer)
    except HTTPException:
        return User(
            user_id="anonymous",
            username="anonymous",
            role=UserRole.ANONYMOUS,
            permissions=[],
        )


def require_role(*roles: UserRole):
    """
    Dependency factory for role-based access control.

    Usage:
        @app.get("/admin", dependencies=[Depends(require_role(UserRole.ADMIN))])
        async def admin_endpoint(): ...
    """
    async def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {[r.value for r in roles]}",
            )
        return user

    return role_checker


async def require_platform_admin(user: User = Depends(get_current_user)) -> User:
    """Платформенный админ: управляет всеми тенантами, планами, чекпоинтами.

    Админ отдельного тенанта (role=ADMIN без is_platform_admin) сюда не
    проходит — его полномочия ограничены своим тенантом.
    """
    if user.role != UserRole.ADMIN or not user.is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform admin privileges required",
        )
    return user


def require_permission(*permissions: str):
    """
    Dependency factory for permission-based access control.

    Usage:
        @app.post("/verify", dependencies=[Depends(require_permission("verify:write"))])
        async def verify_endpoint(): ...
    """
    async def permission_checker(user: User = Depends(get_current_user)) -> User:
        for perm in permissions:
            if perm not in user.permissions and user.role != UserRole.ADMIN:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {permissions}",
                )
        return user

    return permission_checker
