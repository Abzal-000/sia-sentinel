"""
CORS (Cross-Origin Resource Sharing) configuration for SIA Sentinel API.

Allowed origins default to local development ports. For a public deployment
set ``CORS_ALLOW_ORIGINS`` to a comma-separated list of origins, e.g.::

    CORS_ALLOW_ORIGINS=https://app.example.com,https://admin.example.com
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

DEFAULT_DEV_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8501",
    "http://127.0.0.1:8501",
]


def _origins_from_env() -> list[str]:
    """Parse CORS_ALLOW_ORIGINS (comma-separated) or fall back to dev defaults."""
    raw = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
    if not raw:
        return list(DEFAULT_DEV_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def setup_cors(app: FastAPI, allowed_origins: list[str] | None = None) -> None:
    """
    Setup CORS for FastAPI application.

    Args:
        app: FastAPI application instance
        allowed_origins: List of allowed origins. When omitted, origins are
            taken from the ``CORS_ALLOW_ORIGINS`` environment variable, or
            from localhost dev defaults if the variable is not set.
    """
    origins = allowed_origins if allowed_origins is not None else _origins_from_env()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit-Minute", "X-RateLimit-Remaining-Minute"],
        max_age=3600,
    )
