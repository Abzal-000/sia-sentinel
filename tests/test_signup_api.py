from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

import sentinel.api as api_module
import sentinel.auth as auth_module
from sentinel.api import app, rate_limiter
from sentinel.auth import APIKeyManager
from sentinel.billing import BillingEngine
from sentinel.database import AuditJobRecord, get_db_session
from sentinel.outbound_webhooks import OutboundWebhookDispatcher
from sentinel.receipt_registry import ReceiptRegistry
from sentinel.tenancy import TenantManager, UsageMeter

LLM_FLOW = {
    "kind": "llm_flow",
    "name": "signup-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 1,
}


class SignupAPITestCase(unittest.TestCase):
    """Self-service онбординг + разделение привилегий платформа/тенант."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        rate_limiter.reset()

        with get_db_session() as db:
            db.query(AuditJobRecord).delete()

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

        self._original_webhooks = api_module.webhook_dispatcher
        api_module.webhook_dispatcher = OutboundWebhookDispatcher(
            subscriptions_file=str(Path(self._tmp.name) / "webhooks.json")
        )

        self._original_key_manager = auth_module.api_key_manager
        isolated_manager = APIKeyManager(str(Path(self._tmp.name) / "api_keys.json"))
        auth_module.api_key_manager = isolated_manager
        self._original_api_key_manager = api_module.api_key_manager
        api_module.api_key_manager = isolated_manager

        self.client = TestClient(app)

        login = self.client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        self._platform_headers = {
            "Authorization": f"Bearer {login.json()['access_token']}"
        }

    def tearDown(self) -> None:
        api_module.receipt_registry = self._original_registry
        api_module.tenant_manager = self._original_tenants
        api_module.usage_meter = self._original_usage
        api_module.billing_engine = self._original_billing
        api_module.webhook_dispatcher = self._original_webhooks
        auth_module.api_key_manager = self._original_key_manager
        api_module.api_key_manager = self._original_api_key_manager

        if self._original_demo_login is None:
            os.environ.pop("ENABLE_DEMO_LOGIN", None)
        else:
            os.environ["ENABLE_DEMO_LOGIN"] = self._original_demo_login

        self._tmp.cleanup()

    def _signup(self, tenant_id: str = "acme") -> dict:
        response = self.client.post(
            "/v1/signup", json={"name": tenant_id.title(), "tenant_id": tenant_id}
        )
        self.assertEqual(response.status_code, 201)
        return response.json()

    def _tenant_admin_headers(self, tenant_id: str = "acme") -> dict[str, str]:
        return {"X-API-Key": self._signup(tenant_id)["api_key"]}

    # --- Signup ---

    def test_signup_creates_tenant_and_working_key(self) -> None:
        body = self._signup("acme")

        self.assertEqual(body["tenant"]["tenant_id"], "acme")
        self.assertEqual(body["key_info"]["role"], "admin")
        self.assertFalse(body["key_info"]["is_platform_admin"])
        self.assertIn("api_key", body)

        # Ключ сразу работает: аудит под новым тенантом
        response = self.client.post(
            "/v1/audit",
            json={"flow": LLM_FLOW},
            headers={"X-API-Key": body["api_key"]},
        )
        self.assertEqual(response.status_code, 200)

    def test_signup_always_free_plan(self) -> None:
        body = self._signup("acme")
        self.assertEqual(body["tenant"]["plan"], "free")

    def test_signup_duplicate_tenant_400(self) -> None:
        self._signup("acme")

        response = self.client.post(
            "/v1/signup", json={"name": "Acme again", "tenant_id": "acme"}
        )
        self.assertEqual(response.status_code, 400)

    def test_signup_invalid_tenant_id_400(self) -> None:
        response = self.client.post(
            "/v1/signup", json={"name": "Bad", "tenant_id": "UPPER CASE"}
        )
        self.assertEqual(response.status_code, 400)

    def test_signup_generates_tenant_id_when_omitted(self) -> None:
        response = self.client.post("/v1/signup", json={"name": "Anon Org"})

        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json()["tenant"]["tenant_id"])

    # --- Tenant admin: свои ключи ---

    def test_tenant_admin_manages_own_keys(self) -> None:
        admin_headers = self._tenant_admin_headers("acme")

        created = self.client.post(
            "/v1/tenants/acme/api-keys",
            json={"name": "ci-key", "role": "user"},
            headers=admin_headers,
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["key_info"]["tenant_id"], "acme")
        self.assertFalse(created.json()["key_info"]["is_platform_admin"])

        listing = self.client.get(
            "/v1/tenants/acme/api-keys", headers=admin_headers
        ).json()
        # Ключ админа (из signup) + новый ключ
        self.assertEqual(listing["count"], 2)

        key_id = created.json()["key_info"]["key_id"]
        revoked = self.client.delete(
            f"/v1/tenants/acme/api-keys/{key_id}", headers=admin_headers
        )
        self.assertEqual(revoked.status_code, 200)

        # Отозванный ключ больше не проходит авторизацию
        response = self.client.post(
            "/v1/audit",
            json={"flow": LLM_FLOW},
            headers={"X-API-Key": created.json()["api_key"]},
        )
        self.assertEqual(response.status_code, 401)

    def test_tenant_admin_cannot_touch_other_tenant_keys(self) -> None:
        acme_headers = self._tenant_admin_headers("acme")
        globex_body = self._signup("globex")

        response = self.client.post(
            "/v1/tenants/globex/api-keys",
            json={"name": "sneaky", "role": "user"},
            headers=acme_headers,
        )
        self.assertEqual(response.status_code, 403)

        response = self.client.get("/v1/tenants/globex/api-keys", headers=acme_headers)
        self.assertEqual(response.status_code, 403)

        # Чужой ключ нельзя отозвать через свой тенант
        globex_key_id = globex_body["key_info"]["key_id"]
        response = self.client.delete(
            f"/v1/tenants/acme/api-keys/{globex_key_id}", headers=acme_headers
        )
        self.assertEqual(response.status_code, 404)

    def test_tenant_admin_cannot_create_anonymous_key(self) -> None:
        admin_headers = self._tenant_admin_headers("acme")

        response = self.client.post(
            "/v1/tenants/acme/api-keys",
            json={"name": "anon", "role": "anonymous"},
            headers=admin_headers,
        )
        self.assertEqual(response.status_code, 400)

    def test_tenant_admin_cannot_create_key_for_unknown_tenant(self) -> None:
        admin_headers = self._tenant_admin_headers("acme")

        # acme-админ не платформенный: чужой/несуществующий тенант -> 403
        response = self.client.post(
            "/v1/tenants/ghost/api-keys",
            json={"name": "x", "role": "user"},
            headers=admin_headers,
        )
        self.assertEqual(response.status_code, 403)

    # --- Tenant admin: платформенные операции запрещены ---

    def test_tenant_admin_blocked_from_platform_endpoints(self) -> None:
        admin_headers = self._tenant_admin_headers("acme")

        response = self.client.get("/v1/tenants", headers=admin_headers)
        self.assertEqual(response.status_code, 403)

        response = self.client.post(
            "/v1/tenants", json={"name": "New Co", "tenant_id": "newco"},
            headers=admin_headers,
        )
        self.assertEqual(response.status_code, 403)

        response = self.client.post(
            "/v1/billing/plan", json={"plan": "pro"}, headers=admin_headers
        )
        self.assertEqual(response.status_code, 403)

        response = self.client.post(
            "/v1/billing/invoices", json={}, headers=admin_headers
        )
        self.assertEqual(response.status_code, 403)

        response = self.client.post(
            "/v1/ledger/checkpoint", headers=admin_headers
        )
        self.assertEqual(response.status_code, 403)

        response = self.client.post(
            "/v1/auth/api-keys",
            json={"name": "global-key", "role": "user"},
            headers=admin_headers,
        )
        self.assertEqual(response.status_code, 403)

    def test_tenant_admin_can_update_own_settings(self) -> None:
        admin_headers = self._tenant_admin_headers("acme")

        response = self.client.post(
            "/v1/tenants/acme/settings",
            json={"publish_attestations": True},
            headers=admin_headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.json()["tenant"]["metadata"]["publish_attestations"]
        )

    def test_tenant_admin_cannot_update_other_settings(self) -> None:
        admin_headers = self._tenant_admin_headers("acme")
        self._signup("globex")

        response = self.client.post(
            "/v1/tenants/globex/settings",
            json={"publish_attestations": True},
            headers=admin_headers,
        )
        self.assertEqual(response.status_code, 403)

    # --- Платформенный админ сохраняет все права ---

    def test_platform_admin_retains_full_access(self) -> None:
        self._signup("acme")

        listing = self.client.get("/v1/tenants", headers=self._platform_headers)
        self.assertEqual(listing.status_code, 200)

        # Платформенный админ создаёт ключ любому тенанту
        created = self.client.post(
            "/v1/tenants/acme/api-keys",
            json={"name": "platform-issued", "role": "user"},
            headers=self._platform_headers,
        )
        self.assertEqual(created.status_code, 201)

        # И управляет настройками любого тенанта
        response = self.client.post(
            "/v1/tenants/acme/settings",
            json={"publish_attestations": True},
            headers=self._platform_headers,
        )
        self.assertEqual(response.status_code, 200)

    def test_regular_user_cannot_manage_keys(self) -> None:
        self._signup("acme")

        login = self.client.post(
            "/v1/auth/login",
            json={"username": "user", "password": "user123"},
        )
        user_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        response = self.client.post(
            "/v1/tenants/acme/api-keys",
            json={"name": "x", "role": "user"},
            headers=user_headers,
        )
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
