"""
CORS (Cross-Origin Resource Sharing) configuration for SIA Sentinel API.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class StrictCORSMiddleware(BaseHTTPMiddleware):
    """
    Strict CORS middleware with additional security headers.

    Provides:
    - CORS configuration for allowed origins
    - Security headers (already in SecurityMiddleware)
    - HSTS (HTTP Strict Transport Security)
    """

    def __init__(
        self,
        app,
        allow_origins: list[str] = None,
        allow_credentials: bool = True,
        allow_methods: list[str] = None,
        allow_headers: list[str] = None,
    ):
        super().__init__(app)
        self.allow_origins = allow_origins or ["http://localhost:3000", "http://localhost:8501"]
        self.allow_credentials = allow_credentials
        self.allow_methods = allow_methods or ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        self.allow_headers = allow_headers or [
            "Content-Type",
            "Authorization",
            "X-API-Key",
            "X-Request-ID",
        ]

    async def dispatch(self, request: Request, call_next):
        """Process request with CORS headers."""
        # Handle preflight OPTIONS request
        if request.method == "OPTIONS":
            response = Response(status_code=200)
            self._add_cors_headers(request, response)
            return response

        # Process request
        response = await call_next(request)

        # Add CORS headers
        self._add_cors_headers(request, response)

        # Add HSTS header (for production with HTTPS)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

    def _add_cors_headers(self, request: Request, response: Response) -> None:
        """Add CORS headers to response."""
        origin = request.headers.get("origin")

        # Check if origin is allowed
        if origin and (origin in self.allow_origins or "*" in self.allow_origins):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"

        if self.allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"

        response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allow_methods)
        response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allow_headers)
        response.headers["Access-Control-Max-Age"] = "3600"


def setup_cors(app: FastAPI, allowed_origins: list[str] = None) -> None:
    """
    Setup CORS for FastAPI application.

    Args:
        app: FastAPI application instance
        allowed_origins: List of allowed origins (default: localhost:3000, localhost:8501)
    """
    # Use FastAPI's built-in CORSMiddleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins or ["http://localhost:3000", "http://localhost:8501", "http://127.0.0.1:8501"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit-Minute", "X-RateLimit-Remaining-Minute"],
        max_age=3600,
    )
