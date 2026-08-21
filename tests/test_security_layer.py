"""
Tests for security layer.
"""

import unittest
from unittest.mock import MagicMock

from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from sentinel.api import app
from sentinel.security import (
    InputValidator,
    RateLimiter,
    RateLimitConfig,
)


class InputValidatorTestCase(unittest.TestCase):
    """Test input validation."""

    def test_validate_string_valid(self) -> None:
        """Test valid string passes validation."""
        result = InputValidator.validate_string("test", "field", max_length=100)
        self.assertEqual(result, "test")

    def test_validate_string_empty(self) -> None:
        """Test empty string fails validation."""
        with self.assertRaises(HTTPException) as ctx:
            InputValidator.validate_string("", "field", allow_empty=False)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_validate_string_too_long(self) -> None:
        """Test string exceeding max length fails."""
        with self.assertRaises(HTTPException) as ctx:
            InputValidator.validate_string("x" * 101, "field", max_length=100)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_validate_string_xss_blocked(self) -> None:
        """Test XSS patterns are blocked."""
        xss_patterns = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img onerror=alert(1)>",
        ]

        for pattern in xss_patterns:
            with self.assertRaises(HTTPException) as ctx:
                InputValidator.validate_string(pattern, "field")
            self.assertEqual(ctx.exception.status_code, 400)

    def test_validate_agent_id_valid(self) -> None:
        """Test valid agent ID."""
        result = InputValidator.validate_agent_id("agent-001_test")
        self.assertEqual(result, "agent-001_test")

    def test_validate_agent_id_invalid_chars(self) -> None:
        """Test agent ID with invalid characters fails."""
        with self.assertRaises(HTTPException) as ctx:
            InputValidator.validate_agent_id("agent@001!")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_validate_path_traversal_blocked(self) -> None:
        """Test path traversal is blocked."""
        with self.assertRaises(HTTPException) as ctx:
            InputValidator.validate_path("../etc/passwd")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_validate_code_dangerous_imports_blocked(self) -> None:
        """Test dangerous imports in code are blocked."""
        dangerous_code = [
            "import os",
            "import subprocess",
            "from shutil import copy",
        ]

        for code in dangerous_code:
            with self.assertRaises(HTTPException) as ctx:
                InputValidator.validate_code(code)
            self.assertEqual(ctx.exception.status_code, 400)

    def test_validate_list_valid(self) -> None:
        """Test valid list passes validation."""
        result = InputValidator.validate_list(
            ["item1", "item2"],
            "items",
            max_items=10,
        )
        self.assertEqual(len(result), 2)

    def test_validate_list_too_many_items(self) -> None:
        """Test list with too many items fails."""
        with self.assertRaises(HTTPException) as ctx:
            InputValidator.validate_list(
                ["item"] * 11,
                "items",
                max_items=10,
            )
        self.assertEqual(ctx.exception.status_code, 400)


class RateLimiterTestCase(unittest.TestCase):
    """Test rate limiting."""

    def setUp(self) -> None:
        """Create rate limiter with low limits for testing."""
        self.limiter = RateLimiter(
            RateLimitConfig(
                requests_per_minute=5,
                requests_per_hour=10,
                burst_limit=2,
            )
        )

        # Mock request
        self.request = MagicMock(spec=Request)
        self.request.client = MagicMock()
        self.request.client.host = "127.0.0.1"
        self.request.headers = {}

    def test_rate_limit_allows_requests(self) -> None:
        """Test rate limiter allows requests within limit."""
        for _ in range(5):
            self.limiter.check_rate_limit(self.request)

    def test_rate_limit_blocks_excess_requests(self) -> None:
        """Test rate limiter blocks requests exceeding limit."""
        # Use up the limit
        for _ in range(5):
            self.limiter.check_rate_limit(self.request)

        # Next request should fail
        with self.assertRaises(HTTPException) as ctx:
            self.limiter.check_rate_limit(self.request)
        self.assertEqual(ctx.exception.status_code, 429)

    def test_rate_limit_headers(self) -> None:
        """Test rate limit headers are returned."""
        self.limiter.check_rate_limit(self.request)

        headers = self.limiter.get_rate_limit_headers(self.request)

        self.assertIn("X-RateLimit-Limit-Minute", headers)
        self.assertIn("X-RateLimit-Remaining-Minute", headers)
        self.assertEqual(headers["X-RateLimit-Limit-Minute"], "5")
        self.assertEqual(headers["X-RateLimit-Remaining-Minute"], "4")


class SecurityMiddlewareTestCase(unittest.TestCase):
    """Test security middleware."""

    def setUp(self) -> None:
        """Create test client with security middleware."""
        from sentinel.api import rate_limiter

        rate_limiter.reset()
        self.client = TestClient(app)

    def test_security_headers_present(self) -> None:
        """Test security headers are added to responses."""
        response = self.client.get("/health")

        self.assertIn("X-Content-Type-Options", response.headers)
        self.assertIn("X-Frame-Options", response.headers)
        self.assertIn("X-XSS-Protection", response.headers)
        self.assertIn("Content-Security-Policy", response.headers)

        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_rate_limit_headers_present(self) -> None:
        """Test rate limit headers are added to responses."""
        response = self.client.get("/health")

        self.assertIn("X-RateLimit-Limit-Minute", response.headers)
        self.assertIn("X-RateLimit-Remaining-Minute", response.headers)


if __name__ == "__main__":
    unittest.main()
