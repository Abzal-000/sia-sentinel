"""
Tests for authentication and authorization.
"""

import os
import unittest

from fastapi.testclient import TestClient

from sentinel.api import app, rate_limiter
from sentinel.auth import UserRole, jwt_manager


class AuthTestCase(unittest.TestCase):
    """Test authentication endpoints."""

    def setUp(self) -> None:
        """Create test client."""
        rate_limiter.reset()
        self._original_demo_login = os.environ.get("ENABLE_DEMO_LOGIN")
        os.environ["ENABLE_DEMO_LOGIN"] = "1"
        self.client = TestClient(app)

    def tearDown(self) -> None:
        if self._original_demo_login is None:
            os.environ.pop("ENABLE_DEMO_LOGIN", None)
        else:
            os.environ["ENABLE_DEMO_LOGIN"] = self._original_demo_login

    def test_login_admin(self) -> None:
        """Test admin login."""
        response = self.client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["role"], "admin")

    def test_login_invalid_credentials(self) -> None:
        """Test login with invalid credentials."""
        response = self.client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "wrong"},
        )

        self.assertEqual(response.status_code, 401)

    def test_demo_login_disabled_by_default(self) -> None:
        """Demo login must be off unless ENABLE_DEMO_LOGIN is set."""
        os.environ.pop("ENABLE_DEMO_LOGIN", None)

        response = self.client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )

        self.assertEqual(response.status_code, 403)
        os.environ["ENABLE_DEMO_LOGIN"] = "1"

    def test_protected_endpoint_no_auth(self) -> None:
        """Test protected endpoint without authentication."""
        response = self.client.get("/v1/auth/protected")

        self.assertEqual(response.status_code, 401)

    def test_protected_endpoint_with_jwt(self) -> None:
        """Test protected endpoint with JWT token."""
        # Login first
        login_response = self.client.post(
            "/v1/auth/login",
            json={"username": "user", "password": "user123"},
        )
        token = login_response.json()["access_token"]

        # Access protected endpoint
        response = self.client.get(
            "/v1/auth/protected",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["role"], "user")

    def test_admin_only_endpoint_with_user_role(self) -> None:
        """Test admin-only endpoint with user role fails."""
        # Login as user
        login_response = self.client.post(
            "/v1/auth/login",
            json={"username": "user", "password": "user123"},
        )
        token = login_response.json()["access_token"]

        # Try to access admin endpoint
        response = self.client.get(
            "/v1/auth/admin-only",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 403)

    def test_admin_only_endpoint_with_admin_role(self) -> None:
        """Test admin-only endpoint with admin role succeeds."""
        # Login as admin
        login_response = self.client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        token = login_response.json()["access_token"]

        # Access admin endpoint
        response = self.client.get(
            "/v1/auth/admin-only",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["message"], "Welcome, admin!")

    def test_get_current_user_info(self) -> None:
        """Test getting current user info."""
        # Login
        login_response = self.client.post(
            "/v1/auth/login",
            json={"username": "verifier", "password": "verifier123"},
        )
        token = login_response.json()["access_token"]

        # Get user info
        response = self.client.get(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["user"]["username"], "verifier")
        self.assertEqual(data["user"]["role"], "verifier")


class APIKeyTestCase(unittest.TestCase):
    """Test API key authentication."""

    def setUp(self) -> None:
        """Create test client."""
        rate_limiter.reset()
        self._original_demo_login = os.environ.get("ENABLE_DEMO_LOGIN")
        os.environ["ENABLE_DEMO_LOGIN"] = "1"
        self.client = TestClient(app)

    def tearDown(self) -> None:
        if self._original_demo_login is None:
            os.environ.pop("ENABLE_DEMO_LOGIN", None)
        else:
            os.environ["ENABLE_DEMO_LOGIN"] = self._original_demo_login

    def test_create_api_key(self) -> None:
        """Test creating API key (admin only)."""
        # Login as admin
        login_response = self.client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        token = login_response.json()["access_token"]

        # Create API key
        response = self.client.post(
            "/v1/auth/api-keys",
            json={"name": "test-key", "role": "user"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("api_key", data)
        self.assertEqual(data["key_info"]["name"], "test-key")

    def test_create_api_key_non_admin_fails(self) -> None:
        """Test creating API key as non-admin fails."""
        # Login as user
        login_response = self.client.post(
            "/v1/auth/login",
            json={"username": "user", "password": "user123"},
        )
        token = login_response.json()["access_token"]

        # Try to create API key
        response = self.client.post(
            "/v1/auth/api-keys",
            json={"name": "test-key", "role": "user"},
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 403)

    def test_api_key_authentication(self) -> None:
        """Test authenticating with API key."""
        # Login as admin
        login_response = self.client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        token = login_response.json()["access_token"]

        # Create API key
        create_response = self.client.post(
            "/v1/auth/api-keys",
            json={"name": "auth-test-key", "role": "user"},
            headers={"Authorization": f"Bearer {token}"},
        )
        api_key = create_response.json()["api_key"]

        # Use API key to access protected endpoint
        response = self.client.get(
            "/v1/auth/protected",
            headers={"X-API-Key": api_key},
        )

        self.assertEqual(response.status_code, 200)

    def test_list_api_keys(self) -> None:
        """Test listing API keys (admin only)."""
        # Login as admin
        login_response = self.client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        token = login_response.json()["access_token"]

        # List keys
        response = self.client.get(
            "/v1/auth/api-keys",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("count", data)
        self.assertIn("keys", data)

    def test_revoke_api_key(self) -> None:
        """Test revoking API key."""
        # Login as admin
        login_response = self.client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        token = login_response.json()["access_token"]

        # Create API key
        create_response = self.client.post(
            "/v1/auth/api-keys",
            json={"name": "revoke-test-key", "role": "user"},
            headers={"Authorization": f"Bearer {token}"},
        )
        key_id = create_response.json()["key_info"]["key_id"]

        # Revoke key
        response = self.client.delete(
            f"/v1/auth/api-keys/{key_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)


class JWTManagerTestCase(unittest.TestCase):
    """Test JWT manager."""

    def test_create_and_validate_token(self) -> None:
        """Test creating and validating JWT token."""
        token = jwt_manager.create_token(
            user_id="test-user",
            username="testuser",
            role=UserRole.USER,
            permissions=["verify:read"],
        )

        self.assertIsNotNone(token)

        user = jwt_manager.validate_token(token)
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "test-user")
        self.assertEqual(user.username, "testuser")
        self.assertEqual(user.role, UserRole.USER)

    def test_validate_invalid_token(self) -> None:
        """Test validating invalid token."""
        user = jwt_manager.validate_token("invalid-token")
        self.assertIsNone(user)

    def test_validate_expired_token(self) -> None:
        """Test validating expired token."""
        # Create token with very short expiration
        import jwt as pyjwt
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        expired_time = now - timedelta(hours=1)

        payload = {
            "sub": "test-user",
            "username": "testuser",
            "role": "user",
            "permissions": [],
            "iat": int(expired_time.timestamp()),
            "exp": int((expired_time + timedelta(minutes=5)).timestamp()),
        }

        token = pyjwt.encode(payload, jwt_manager.secret_key, algorithm=jwt_manager.algorithm)

        user = jwt_manager.validate_token(token)
        self.assertIsNone(user)


if __name__ == "__main__":
    unittest.main()
