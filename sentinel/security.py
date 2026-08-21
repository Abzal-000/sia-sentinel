"""
Security layer for SIA Sentinel API.

Provides:
- Input validation and sanitization
- Rate limiting
- Request size limits
- SQL injection prevention
- XSS protection
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Optional

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


# === Input Validation ===

class InputValidator:
    """Validates and sanitizes API inputs."""

    # Dangerous patterns that should be blocked
    DANGEROUS_PATTERNS = [
        r"<script",  # XSS
        r"javascript:",  # XSS
        r"on\w+\s*=",  # Event handlers (onclick, onload, etc.)
        r"eval\s*\(",  # Code injection
        r"exec\s*\(",  # Code injection
        r"__import__\s*\(",  # Python import injection
        r"import\s+os",  # OS module import
        r"import\s+subprocess",  # Subprocess import
        r"from\s+subprocess",  # Subprocess import
        r"import\s+shutil",  # Shutil import
        r"from\s+shutil",  # Shutil import
    ]

    # Maximum lengths for different input types
    MAX_LENGTHS = {
        "agent_id": 256,
        "description": 4096,
        "target_path": 1024,
        "target_symbol": 256,
        "code": 1_000_000,  # 1MB max code size
        "hash": 128,
        "requirement": 128,
    }

    @classmethod
    def validate_string(
        cls,
        value: str,
        field_name: str,
        max_length: Optional[int] = None,
        allow_empty: bool = False,
    ) -> str:
        """
        Validate and sanitize string input.

        Args:
            value: Input string
            field_name: Name of field (for error messages)
            max_length: Maximum allowed length
            allow_empty: Whether empty string is allowed

        Returns:
            Sanitized string

        Raises:
            HTTPException: If validation fails
        """
        if not isinstance(value, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} must be a string",
            )

        # Check empty
        if not allow_empty and not value.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} cannot be empty",
            )

        # Check length
        if max_length is None:
            max_length = cls.MAX_LENGTHS.get(field_name, 1024)

        if len(value) > max_length:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} exceeds maximum length of {max_length}",
            )

        # Check for null bytes and control characters
        if '\x00' in value or '\0' in value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} contains null bytes",
            )

        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"{field_name} contains prohibited content",
                )

        return value.strip()

    @classmethod
    def validate_agent_id(cls, agent_id: str) -> str:
        """Validate agent ID."""
        validated = cls.validate_string(agent_id, "agent_id", max_length=256)

        # Agent ID should be alphanumeric with hyphens/underscores
        if not re.match(r"^[a-zA-Z0-9_-]+$", validated):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="agent_id must contain only alphanumeric characters, hyphens, and underscores",
            )

        return validated

    @classmethod
    def validate_code(cls, code: str, field_name: str = "code") -> str:
        """Validate code input."""
        return cls.validate_string(
            code,
            field_name,
            max_length=cls.MAX_LENGTHS["code"],
            allow_empty=True,
        )

    @classmethod
    def validate_path(cls, path: str) -> str:
        """Validate file path."""
        validated = cls.validate_string(path, "target_path", max_length=1024)

        # Prevent path traversal
        if ".." in validated or validated.startswith("/"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid path: path traversal not allowed",
            )

        return validated

    @classmethod
    def validate_list(
        cls,
        items: list,
        field_name: str,
        max_items: int = 100,
        item_validator: Optional[Callable] = None,
    ) -> list:
        """Validate list input."""
        if not isinstance(items, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} must be a list",
            )

        if len(items) > max_items:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name} exceeds maximum of {max_items} items",
            )

        if item_validator:
            return [item_validator(item) for item in items]

        return items


# === Rate Limiting ===

@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_limit: int = 10


@dataclass
class RateLimitInfo:
    """Rate limit information for a client."""
    requests_minute: int = 0
    requests_hour: int = 0
    last_reset_minute: float = field(default_factory=time.time)
    last_reset_hour: float = field(default_factory=time.time)


class RateLimiter:
    """
    In-memory rate limiter.

    In production, use Redis for distributed rate limiting.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self.clients: dict[str, RateLimitInfo] = defaultdict(RateLimitInfo)

    def reset(self) -> None:
        """Clear all per-client counters (used to isolate test runs)."""
        self.clients.clear()

    def _get_client_key(self, request: Request) -> str:
        """Get unique key for client (IP + API key if present)."""
        client_ip = request.client.host if request.client else "unknown"
        api_key = request.headers.get("X-API-Key", "")

        # Hash the key for privacy
        key = f"{client_ip}:{api_key}"
        return hashlib.sha256(key.encode()).hexdigest()[:32]

    def check_rate_limit(self, request: Request) -> None:
        """
        Check if request is within rate limits.

        Raises:
            HTTPException: If rate limit exceeded
        """
        client_key = self._get_client_key(request)
        info = self.clients[client_key]
        now = time.time()

        # Reset counters if time window has passed
        if now - info.last_reset_minute > 60:
            info.requests_minute = 0
            info.last_reset_minute = now

        if now - info.last_reset_hour > 3600:
            info.requests_hour = 0
            info.last_reset_hour = now

        # Check limits
        if info.requests_minute >= self.config.requests_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: {self.config.requests_per_minute} requests per minute",
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(self.config.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                },
            )

        if info.requests_hour >= self.config.requests_per_hour:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: {self.config.requests_per_hour} requests per hour",
                headers={
                    "Retry-After": "3600",
                    "X-RateLimit-Limit": str(self.config.requests_per_hour),
                    "X-RateLimit-Remaining": "0",
                },
            )

        # Increment counters
        info.requests_minute += 1
        info.requests_hour += 1

    def get_rate_limit_headers(self, request: Request) -> dict[str, str]:
        """Get rate limit headers for response."""
        client_key = self._get_client_key(request)
        info = self.clients[client_key]

        return {
            "X-RateLimit-Limit-Minute": str(self.config.requests_per_minute),
            "X-RateLimit-Remaining-Minute": str(
                max(0, self.config.requests_per_minute - info.requests_minute)
            ),
            "X-RateLimit-Limit-Hour": str(self.config.requests_per_hour),
            "X-RateLimit-Remaining-Hour": str(
                max(0, self.config.requests_per_hour - info.requests_hour)
            ),
        }


# === Security Middleware ===

class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware for FastAPI.

    Provides:
    - Rate limiting
    - Request size limits
    - Security headers
    """

    def __init__(
        self,
        app,
        rate_limiter: Optional[RateLimiter] = None,
        max_request_size: int = 10 * 1024 * 1024,  # 10MB
    ):
        super().__init__(app)
        self.rate_limiter = rate_limiter or RateLimiter()
        self.max_request_size = max_request_size

    async def dispatch(self, request: Request, call_next):
        """Process request with security checks."""
        # Check request size
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_request_size:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"detail": "Request too large"},
            )

        # Check rate limit
        try:
            self.rate_limiter.check_rate_limit(request)
        except HTTPException as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=exc.headers,
            )

        # Process request
        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"

        # Add rate limit headers
        rate_headers = self.rate_limiter.get_rate_limit_headers(request)
        for key, value in rate_headers.items():
            response.headers[key] = value

        return response


# === Utility Functions ===

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal and other attacks.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    # Remove path separators
    filename = filename.replace("/", "").replace("\\", "")

    # Remove dangerous characters
    filename = re.sub(r"[^\w\-_.]", "", filename)

    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255 - len(ext)] + ext

    return filename


def hash_sensitive_data(data: str) -> str:
    """
    Hash sensitive data (e.g., API keys, tokens).

    Args:
        data: Sensitive data to hash

    Returns:
        SHA256 hash
    """
    return hashlib.sha256(data.encode()).hexdigest()
