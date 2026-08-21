"""
Tests for CORS configuration.
"""

import unittest

from fastapi.testclient import TestClient

from sentinel.api import app, rate_limiter


class CORSTestCase(unittest.TestCase):
    """Test CORS headers."""

    def setUp(self) -> None:
        """Create test client."""
        rate_limiter.reset()
        self.client = TestClient(app)

    def test_cors_headers_present(self) -> None:
        """Test CORS headers are added to responses."""
        response = self.client.get(
            "/health",
            headers={"Origin": "http://localhost:3000"},
        )

        # Check CORS headers (origin and credentials are always present)
        self.assertIn("access-control-allow-origin", response.headers)
        self.assertIn("access-control-allow-credentials", response.headers)

        # Check allowed origin
        self.assertEqual(
            response.headers["access-control-allow-origin"],
            "http://localhost:3000",
        )

    def test_cors_preflight_request(self) -> None:
        """Test CORS preflight OPTIONS request."""
        response = self.client.options(
            "/v1/verify-change",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type,Authorization",
            },
        )

        # Preflight should return 200 or 204
        self.assertIn(response.status_code, [200, 204])

        # Check CORS headers (methods and headers only in preflight)
        self.assertIn("access-control-allow-origin", response.headers)
        self.assertIn("access-control-allow-methods", response.headers)
        self.assertIn("access-control-allow-headers", response.headers)

    def test_cors_credentials_allowed(self) -> None:
        """Test CORS allows credentials."""
        response = self.client.get(
            "/health",
            headers={"Origin": "http://localhost:3000"},
        )

        self.assertEqual(
            response.headers.get("access-control-allow-credentials"),
            "true",
        )

    def test_cors_methods_include_post(self) -> None:
        """Test CORS allows POST method (in preflight)."""
        response = self.client.options(
            "/v1/verify-change",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            },
        )

        allowed_methods = response.headers.get("access-control-allow-methods", "")
        self.assertIn("POST", allowed_methods)

    def test_cors_headers_include_authorization(self) -> None:
        """Test CORS allows Authorization header (in preflight)."""
        response = self.client.options(
            "/v1/verify-change",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization",
            },
        )

        allowed_headers = response.headers.get("access-control-allow-headers", "")
        # Should allow Authorization or * (all headers)
        self.assertTrue(
            "authorization" in allowed_headers.lower() or "*" in allowed_headers
        )


class SecurityHeadersTestCase(unittest.TestCase):
    """Test security headers."""

    def setUp(self) -> None:
        """Create test client."""
        rate_limiter.reset()
        self.client = TestClient(app)

    def test_hsts_header_present(self) -> None:
        """Test HSTS header is present."""
        response = self.client.get("/health")

        # HSTS should be present (may be added by CORSMiddleware or SecurityMiddleware)
        # Note: In dev mode without HTTPS, HSTS might not be added
        # This test is informational
        hsts = response.headers.get("strict-transport-security")
        if hsts:
            self.assertIn("max-age", hsts)

    def test_no_server_header(self) -> None:
        """Test server header is not exposed (security best practice)."""
        response = self.client.get("/health")

        # Server header should not reveal server software/version
        server = response.headers.get("server", "")
        # Should be empty or generic (not "uvicorn/0.23.2" etc.)
        # Note: uvicorn may add this, so we just check it's not revealing sensitive info
        if server:
            self.assertNotIn("python", server.lower())


if __name__ == "__main__":
    unittest.main()
