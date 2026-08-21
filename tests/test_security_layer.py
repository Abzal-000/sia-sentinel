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


class InputValidatorJsonBodyTestCase(unittest.TestCase):
    """D9: универсальная валидация JSON-тел (null-байты, управляющие символы)."""

    def test_null_byte_rejected(self) -> None:
        with self.assertRaises(HTTPException) as ctx:
            InputValidator.validate_json_body({"description": "ok\x00evil"})
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("null bytes", ctx.exception.detail)

    def test_control_char_rejected(self) -> None:
        with self.assertRaises(HTTPException) as ctx:
            InputValidator.validate_json_body({"nested": {"field": "bad\x01char"}})
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("control characters", ctx.exception.detail)

    def test_newlines_tabs_and_code_allowed(self) -> None:
        # Переводы строк/табуляция и обычный код (включая import os) легитимны
        body = {
            "code": "import os\n\ndef f():\n\treturn os.getcwd()\n",
            "items": ["a", "b"],
            "count": 3,
            "flag": True,
            "nothing": None,
        }
        InputValidator.validate_json_body(body)  # не должно бросать


class MiddlewareBodyValidationTestCase(unittest.TestCase):
    """D9: SecurityMiddleware отклоняет опасные JSON-тела до авторизации."""

    def setUp(self) -> None:
        from sentinel.api import rate_limiter

        rate_limiter.reset()
        self.client = TestClient(app)

    def test_null_byte_body_rejected_with_400(self) -> None:
        response = self.client.post(
            "/v1/verify-change",
            json={"agent_id": "a", "description": "ok\x00evil"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("null bytes", response.json()["detail"])

    def test_control_char_body_rejected_with_400(self) -> None:
        response = self.client.post(
            "/v1/verify-change",
            json={"agent_id": "a", "description": "bad\x01char"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("control characters", response.json()["detail"])

    def test_legitimate_code_not_blocked_by_middleware(self) -> None:
        # Код с import os проходит middleware (продукт аудитит код);
        # без авторизации запрос упирается в 401, а не в 400 middleware.
        response = self.client.post(
            "/v1/verify-change",
            json={
                "agent_id": "a",
                "description": "refactor",
                "target_path": "src/test.py",
                "current_code": "import os\n",
                "proposed_code": "import os\nimport sys\n",
            },
        )
        self.assertEqual(response.status_code, 401)

    def test_malformed_json_rejected_with_400(self) -> None:
        response = self.client.post(
            "/v1/verify-change",
            content=b"{not-valid-json",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid JSON", response.json()["detail"])


class TrustProxyTestCase(unittest.TestCase):
    """D10: X-Forwarded-For учитывается только при TRUST_PROXY=1."""

    def _make_request(self, client_host: str, forwarded: str | None) -> Request:
        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = client_host
        request.headers = {"x-forwarded-for": forwarded} if forwarded else {}
        return request

    def test_forwarded_header_ignored_without_trust_proxy(self) -> None:
        import os

        os.environ.pop("TRUST_PROXY", None)
        limiter = RateLimiter()

        plain = limiter._get_client_key(self._make_request("10.0.0.1", None))
        spoofed = limiter._get_client_key(
            self._make_request("10.0.0.1", "1.2.3.4, 10.0.0.1")
        )

        # Подделка заголовка не меняет ключ клиента
        self.assertEqual(plain, spoofed)

    def test_forwarded_first_hop_used_with_trust_proxy(self) -> None:
        import os

        os.environ["TRUST_PROXY"] = "1"
        try:
            limiter = RateLimiter()

            via_proxy = limiter._get_client_key(
                self._make_request("10.0.0.1", "1.2.3.4, 10.0.0.1")
            )
            direct = limiter._get_client_key(self._make_request("1.2.3.4", None))

            # Первый хоп за прокси совпадает с прямым подключением того же IP
            self.assertEqual(via_proxy, direct)

            other = limiter._get_client_key(self._make_request("10.0.0.1", None))
            self.assertNotEqual(via_proxy, other)
        finally:
            os.environ.pop("TRUST_PROXY", None)


if __name__ == "__main__":
    unittest.main()
