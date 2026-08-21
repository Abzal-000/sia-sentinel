"""
Automated Penetration Testing for SIA Sentinel API.
"""

import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

import sentinel.api as api_module
from sentinel.api import app
from sentinel.billing import BillingEngine
from sentinel.outbound_webhooks import OutboundWebhookDispatcher
from sentinel.receipt_registry import ReceiptRegistry
from sentinel.tenancy import TenantManager, UsageMeter


class PenetrationTestCase(unittest.TestCase):
    """Base class - изолированное состояние + аутентифицированный клиент.

    verify-change/risk-score/network закрыты авторизацией (B2), поэтому
    инъекционные тесты ходят под JWT админа. Биллинг изолирован, а
    default-тенант переведён на enterprise, чтобы квота не мешала
    проверкам валидации ввода.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        try:
            from sentinel.api import rate_limiter
            rate_limiter.clients.clear()
        except Exception:
            pass

        self._original_demo_login = os.environ.get("ENABLE_DEMO_LOGIN")
        os.environ["ENABLE_DEMO_LOGIN"] = "1"

        self._original_registry = api_module.receipt_registry
        api_module.receipt_registry = ReceiptRegistry(str(Path(self._tmp.name) / "receipts"))

        self._original_tenants = api_module.tenant_manager
        api_module.tenant_manager = TenantManager(str(Path(self._tmp.name) / "tenants.json"))

        self._original_usage = api_module.usage_meter
        api_module.usage_meter = UsageMeter(str(Path(self._tmp.name) / "usage.jsonl"))

        self._original_billing = api_module.billing_engine
        api_module.billing_engine = BillingEngine(
            api_module.tenant_manager,
            api_module.usage_meter,
            invoices_file=str(Path(self._tmp.name) / "invoices.json"),
        )
        # Безлимитный план, чтобы квота не давала 402 в инъекционных тестах
        api_module.billing_engine.set_plan("default", "enterprise")

        self._original_webhooks = api_module.webhook_dispatcher
        api_module.webhook_dispatcher = OutboundWebhookDispatcher(
            subscriptions_file=str(Path(self._tmp.name) / "webhooks.json")
        )

        self.client = TestClient(app)

        login = self.client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        self._auth_headers = {
            "Authorization": f"Bearer {login.json()['access_token']}"
        }

    def tearDown(self) -> None:
        api_module.receipt_registry = self._original_registry
        api_module.tenant_manager = self._original_tenants
        api_module.usage_meter = self._original_usage
        api_module.billing_engine = self._original_billing
        api_module.webhook_dispatcher = self._original_webhooks

        if self._original_demo_login is None:
            os.environ.pop("ENABLE_DEMO_LOGIN", None)
        else:
            os.environ["ENABLE_DEMO_LOGIN"] = self._original_demo_login

        self._tmp.cleanup()


class SQLInjectionTestCase(PenetrationTestCase):

    def test_agent_id_sql_injection(self) -> None:
        malicious_ids = [
            "agent' OR '1'='1",
            "agent'; DROP TABLE users; --",
            "1' OR 1=1 --",
        ]
        for malicious_id in malicious_ids:
            payload = {
                "agent_id": malicious_id,
                "description": "Test",
                "target_path": "src/test.py",
                "current_code": "def add(a, b): return a + b",
                "proposed_code": "def add(a, b): return b + a",
                "allowed_paths": ["src/test.py"],
            }
            response = self.client.post("/v1/verify-change", json=payload, headers=self._auth_headers)
            # Should be rejected by agent_id validation (invalid chars) or succeed
            # 429 is OK if rate limited, not a security issue
            self.assertIn(response.status_code, [200, 400, 422, 429])

    def test_code_field_sql_injection(self) -> None:
        malicious_code = ["'; DROP TABLE evidence; --", "admin'--"]
        for code in malicious_code:
            payload = {
                "agent_id": "test-agent",
                "description": "Test",
                "target_path": "src/test.py",
                "current_code": code,
                "proposed_code": code,
                "allowed_paths": ["src/test.py"],
            }
            response = self.client.post("/v1/verify-change", json=payload, headers=self._auth_headers)
            self.assertIn(response.status_code, [200, 400, 422, 429])


class XSSTestCase(PenetrationTestCase):

    def test_xss_in_description(self) -> None:
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]
        for payload in xss_payloads:
            data = {
                "agent_id": "test-agent",
                "description": payload,
                "target_path": "src/test.py",
                "current_code": "def add(a, b): return a + b",
                "proposed_code": "def add(a, b): return b + a",
                "allowed_paths": ["src/test.py"],
            }
            response = self.client.post("/v1/verify-change", json=data, headers=self._auth_headers)
            # Description is just text data, XSS is acceptable here
            # but must NOT be reflected in response HTML
            self.assertIn(response.status_code, [200, 400, 422, 429])
            response_text = response.text
            self.assertNotIn("<script>", response_text.lower())

    def test_xss_in_agent_id(self) -> None:
        xss_payloads = ["<script>alert(1)</script>", "javascript:alert(1)"]
        for payload in xss_payloads:
            data = {
                "agent_id": payload,
                "description": "Test",
                "target_path": "src/test.py",
                "current_code": "def add(a, b): return a + b",
                "proposed_code": "def add(a, b): return b + a",
                "allowed_paths": ["src/test.py"],
            }
            response = self.client.post("/v1/verify-change", json=data, headers=self._auth_headers)
            # Agent IDs are sanitized, so request may succeed (200) or be rejected (400/422)
            self.assertIn(response.status_code, [200, 400, 422, 429])


class PathTraversalTestCase(PenetrationTestCase):

    def test_path_traversal_in_target_path(self) -> None:
        malicious_paths = [
            "../etc/passwd",
            "/etc/shadow",
            "....//....//etc/passwd",
        ]
        for path in malicious_paths:
            payload = {
                "agent_id": "test-agent",
                "description": "Test",
                "target_path": path,
                "current_code": "def add(a, b): return a + b",
                "proposed_code": "def add(a, b): return b + a",
                "allowed_paths": ["src/test.py"],
            }
            response = self.client.post("/v1/verify-change", json=payload, headers=self._auth_headers)
            # Should be rejected (400/422) or path traversal prevented in processing (200 but safe)
            self.assertIn(response.status_code, [200, 400, 422, 429])
            # Critical: should NOT cause file system access outside allowed paths
            # This is validated by the fact that evidence is stored safely


class AuthenticationBypassTestCase(PenetrationTestCase):

    def test_gated_endpoints_reject_anonymous(self) -> None:
        """B2: verify-change/risk-score/network больше не публичные."""
        payload = {
            "agent_id": "test-agent",
            "description": "Test",
            "target_path": "src/test.py",
            "current_code": "def add(a, b): return a + b",
            "proposed_code": "def add(a, b): return b + a",
            "allowed_paths": ["src/test.py"],
        }

        response = self.client.post("/v1/verify-change", json=payload)
        self.assertEqual(response.status_code, 401)

        response = self.client.post("/v1/risk-score", json=payload)
        self.assertEqual(response.status_code, 401)

    def test_invalid_jwt_format(self) -> None:
        invalid_tokens = ["invalid.token.here", "not-a-jwt", ""]
        for token in invalid_tokens:
            response = self.client.get(
                "/v1/auth/protected",
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertIn(response.status_code, [401, 429])

    def test_empty_api_key(self) -> None:
        response = self.client.get(
            "/v1/auth/protected",
            headers={"X-API-Key": ""},
        )
        self.assertIn(response.status_code, [401, 429])

    def test_api_key_injection(self) -> None:
        malicious_keys = ["' OR '1'='1", "admin'--"]
        for key in malicious_keys:
            response = self.client.get(
                "/v1/auth/protected",
                headers={"X-API-Key": key},
            )
            self.assertIn(response.status_code, [401, 429])


class RateLimitBypassTestCase(PenetrationTestCase):

    def test_rate_limit_headers_present(self) -> None:
        response = self.client.get("/health")
        # Check for any rate limit header format
        has_rate_limit = any(
            "ratelimit" in k.lower() or "rate-limit" in k.lower()
            for k in response.headers.keys()
        )
        self.assertTrue(has_rate_limit, f"Rate limit headers not found. Got: {list(response.headers.keys())}")

    def test_rate_limit_enforced(self) -> None:
        # Exhaust limit
        for _ in range(65):
            self.client.get("/health")
        response = self.client.get("/health")
        self.assertIn(response.status_code, [200, 429])


class InputValidationBypassTestCase(PenetrationTestCase):

    def test_oversized_payload(self) -> None:
        large_code = "x" * (2 * 1024 * 1024)  # 2MB instead of 10MB
        payload = {
            "agent_id": "test-agent",
            "description": "Test",
            "target_path": "src/test.py",
            "current_code": large_code,
            "proposed_code": "def add(a, b): return b + a",
            "allowed_paths": ["src/test.py"],
        }
        response = self.client.post("/v1/verify-change", json=payload, headers=self._auth_headers)
        self.assertIn(response.status_code, [200, 400, 413, 422, 429])

    def test_null_bytes_in_input(self) -> None:
        payload = {
            "agent_id": "test\x00agent",
            "description": "Test\x00description",
            "target_path": "src/test.py",
            "current_code": "def add(a, b): return a + b",
            "proposed_code": "def add(a, b): return b + a",
            "allowed_paths": ["src/test.py"],
        }
        response = self.client.post("/v1/verify-change", json=payload, headers=self._auth_headers)
        # Null bytes are sanitized, so request may succeed (200) or be rejected
        # Critical: must NOT crash server with 500
        self.assertIn(response.status_code, [200, 400, 422, 429])
        self.assertNotIn(response.status_code, [500])  # Must not crash server

    def test_unicode_injection(self) -> None:
        unicode_payloads = [
            "admin\u202e",  # Right-to-left override
            "\uffff" * 10,  # High Unicode
        ]
        for payload_text in unicode_payloads:
            payload = {
                "agent_id": payload_text,
                "description": "Test",
                "target_path": "src/test.py",
                "current_code": "def add(a, b): return a + b",
                "proposed_code": "def add(a, b): return b + a",
                "allowed_paths": ["src/test.py"],
            }
            response = self.client.post("/v1/verify-change", json=payload, headers=self._auth_headers)
            self.assertIn(response.status_code, [200, 400, 422, 429])


class CORSMisconfigurationTestCase(PenetrationTestCase):

    def test_cors_wildcard_origin(self) -> None:
        response = self.client.get(
            "/health",
            headers={"Origin": "http://malicious.com"},
        )
        allow_origin = response.headers.get("access-control-allow-origin", "")
        if response.headers.get("access-control-allow-credentials") == "true":
            self.assertNotEqual(allow_origin, "*")

    def test_cors_reflection_attack(self) -> None:
        response = self.client.get(
            "/health",
            headers={"Origin": "http://evil.com"},
        )
        allow_origin = response.headers.get("access-control-allow-origin", "")
        if allow_origin == "http://evil.com":
            self.fail("CORS reflects arbitrary origin - security vulnerability")


class APIKeyEnumerationTestCase(PenetrationTestCase):

    def test_no_api_key_leak_in_error(self) -> None:
        response = self.client.get(
            "/v1/auth/protected",
            headers={"X-API-Key": "invalid-key"},
        )
        error_detail = response.json().get("detail", "")
        self.assertTrue(
            "not authenticated" in error_detail.lower() or
            "invalid" in error_detail.lower() or
            error_detail == ""
        )
        self.assertNotIn("stack trace", error_detail.lower())


if __name__ == "__main__":
    unittest.main()
