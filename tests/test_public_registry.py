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
    "name": "public-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 1,
}


class PublicRegistryTestCase(unittest.TestCase):
    """Opt-in публичный реестр + HTML-портал верификации."""

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
        self._admin_headers = {
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

    def _create_tenant_with_audit(self, tenant_id: str) -> str:
        """Создаёт тенант, ключ, прогоняет аудит; возвращает registry_id."""
        self.client.post(
            "/v1/tenants",
            json={"name": tenant_id.title(), "tenant_id": tenant_id},
            headers=self._admin_headers,
        )

        key_response = self.client.post(
            "/v1/auth/api-keys",
            json={"name": f"{tenant_id}-key", "role": "user", "tenant_id": tenant_id},
            headers=self._admin_headers,
        )
        headers = {"X-API-Key": key_response.json()["api_key"]}

        response = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=headers
        )
        self.assertEqual(response.status_code, 200)
        return response.json()["registry_id"]

    def _publish(self, tenant_id: str, flag: bool = True) -> None:
        response = self.client.post(
            f"/v1/tenants/{tenant_id}/settings",
            json={"publish_attestations": flag},
            headers=self._admin_headers,
        )
        self.assertEqual(response.status_code, 200)

    # --- Публичный список ---

    def test_public_list_empty_by_default(self) -> None:
        self._create_tenant_with_audit("acme")

        listing = self.client.get("/v1/attestations").json()
        self.assertEqual(listing["count"], 0)

    def test_public_list_requires_no_auth(self) -> None:
        response = self.client.get("/v1/attestations")
        self.assertEqual(response.status_code, 200)

    def test_opted_in_tenant_appears_in_public_list(self) -> None:
        registry_id = self._create_tenant_with_audit("acme")
        self._publish("acme")

        listing = self.client.get("/v1/attestations").json()

        self.assertEqual(listing["count"], 1)
        card = listing["attestations"][0]
        self.assertEqual(card["registry_id"], registry_id)
        self.assertEqual(card["flow_name"], "public-flow")
        self.assertTrue(card["savings_verified"])
        self.assertIsNotNone(card["savings_ratio"])

    def test_opt_out_hides_tenant_again(self) -> None:
        registry_id = self._create_tenant_with_audit("acme")
        self._publish("acme")
        self._publish("acme", flag=False)

        listing = self.client.get("/v1/attestations").json()
        self.assertEqual(listing["count"], 0)

        # Но индивидуальный доступ по id остаётся (badge ссылается на него)
        attestation = self.client.get(f"/v1/attestations/{registry_id}")
        self.assertEqual(attestation.status_code, 200)

    def test_multiple_tenants_filtered(self) -> None:
        acme_id = self._create_tenant_with_audit("acme")
        self._create_tenant_with_audit("globex")
        self._publish("acme")

        listing = self.client.get("/v1/attestations").json()

        self.assertEqual(listing["count"], 1)
        self.assertEqual(listing["attestations"][0]["registry_id"], acme_id)

    # --- Settings-эндпоинт ---

    def test_settings_admin_only(self) -> None:
        self._create_tenant_with_audit("acme")

        response = self.client.post(
            "/v1/tenants/acme/settings", json={"publish_attestations": True}
        )
        self.assertEqual(response.status_code, 401)

    def test_settings_unknown_tenant_404(self) -> None:
        response = self.client.post(
            "/v1/tenants/ghost/settings",
            json={"publish_attestations": True},
            headers=self._admin_headers,
        )
        self.assertEqual(response.status_code, 404)

    def test_settings_empty_body_400(self) -> None:
        self._create_tenant_with_audit("acme")

        response = self.client.post(
            "/v1/tenants/acme/settings", json={}, headers=self._admin_headers
        )
        self.assertEqual(response.status_code, 400)

    # --- HTML-портал ---

    def test_portal_page_renders_verdict(self) -> None:
        registry_id = self._create_tenant_with_audit("acme")

        response = self.client.get(f"/attestations/{registry_id}")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("VERIFIED", response.text)
        self.assertIn(registry_id, response.text)
        self.assertIn("badge.svg", response.text)

    def test_portal_unknown_attestation_404(self) -> None:
        response = self.client.get("/attestations/missing")
        self.assertEqual(response.status_code, 404)

    def test_registry_page_lists_opted_in(self) -> None:
        registry_id = self._create_tenant_with_audit("acme")
        self._publish("acme")

        response = self.client.get("/registry")

        self.assertEqual(response.status_code, 200)
        self.assertIn(registry_id[:12], response.text)
        self.assertIn("public-flow", response.text)

    def test_registry_page_empty(self) -> None:
        response = self.client.get("/registry")

        self.assertEqual(response.status_code, 200)
        self.assertIn("No published attestations yet", response.text)

    # п.10: витрина на трёх языках (kk/ru — суверенное позиционирование)

    def test_registry_page_lang_ru(self) -> None:
        response = self.client.get("/registry", params={"lang": "ru"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("Публичный реестр аттестаций", response.text)
        self.assertIn("Опубликованных аттестаций пока нет", response.text)
        self.assertIn('lang="ru"', response.text)

    def test_registry_page_lang_kk(self) -> None:
        response = self.client.get("/registry", params={"lang": "kk"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("Аттестаттаулардың қоғамдық тізілімі", response.text)
        self.assertIn("Әзірге жарияланған аттестаттау жоқ", response.text)

    def test_registry_page_lang_unknown_falls_back_to_en(self) -> None:
        response = self.client.get("/registry", params={"lang": "de"})

        self.assertEqual(response.status_code, 200)
        self.assertIn("Public Attestation Registry", response.text)

    def test_portal_page_lang_ru(self) -> None:
        registry_id = self._create_tenant_with_audit("acme")

        response = self.client.get(
            f"/attestations/{registry_id}", params={"lang": "ru"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("ПОДТВЕРЖДЕНО", response.text)
        self.assertIn("Аттестация Proof-of-Savings", response.text)

    def test_portal_page_lang_kk(self) -> None:
        registry_id = self._create_tenant_with_audit("acme")

        response = self.client.get(
            f"/attestations/{registry_id}", params={"lang": "kk"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Proof-of-Savings аттестаттауы", response.text)
        self.assertIn("РАСТАЛДЫ", response.text)


if __name__ == "__main__":
    unittest.main()
