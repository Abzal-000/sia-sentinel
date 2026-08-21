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
    "name": "billing-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 1,
}


class BillingAPITestCase(unittest.TestCase):
    """Биллинг-эндпоинты: планы, квоты (402), инвойсы, изоляция."""

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

    def _create_tenant(self, tenant_id: str, plan: str = "free") -> None:
        response = self.client.post(
            "/v1/tenants",
            json={"name": tenant_id.title(), "tenant_id": tenant_id, "plan": plan},
            headers=self._admin_headers,
        )
        self.assertEqual(response.status_code, 201)

    def _tenant_headers(self, tenant_id: str) -> dict[str, str]:
        response = self.client.post(
            "/v1/auth/api-keys",
            json={"name": f"{tenant_id}-key", "role": "user", "tenant_id": tenant_id},
            headers=self._admin_headers,
        )
        self.assertEqual(response.status_code, 200)
        return {"X-API-Key": response.json()["api_key"]}

    # --- Каталог планов ---

    def test_plans_catalog_is_public(self) -> None:
        response = self.client.get("/v1/billing/plans")

        self.assertEqual(response.status_code, 200)
        names = {p["name"] for p in response.json()["plans"]}
        self.assertEqual(names, {"free", "pro", "enterprise"})

    def test_create_tenant_unknown_plan_400(self) -> None:
        response = self.client.post(
            "/v1/tenants",
            json={"name": "Acme", "tenant_id": "acme", "plan": "platinum"},
            headers=self._admin_headers,
        )

        self.assertEqual(response.status_code, 400)

    # --- Текущий план и квоты ---

    def test_get_plan_requires_auth(self) -> None:
        response = self.client.get("/v1/billing/plan")
        self.assertEqual(response.status_code, 401)

    def test_get_plan_shows_quota_status(self) -> None:
        self._create_tenant("acme", plan="free")
        headers = self._tenant_headers("acme")

        response = self.client.get("/v1/billing/plan", headers=headers)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["plan"]["name"], "free")
        self.assertEqual(body["quota"]["categories"]["audits"]["limit"], 10)
        self.assertEqual(body["quota"]["categories"]["audits"]["used"], 0)

    # --- Смена плана ---

    def test_change_plan_admin_only(self) -> None:
        self._create_tenant("acme")
        headers = self._tenant_headers("acme")

        # Роль user — недостаточно
        response = self.client.post(
            "/v1/billing/plan", json={"plan": "pro"}, headers=headers
        )
        self.assertEqual(response.status_code, 403)

    def test_change_plan_unknown_plan_400(self) -> None:
        response = self.client.post(
            "/v1/billing/plan", json={"plan": "platinum"}, headers=self._admin_headers
        )
        self.assertEqual(response.status_code, 400)

    def test_change_plan_updates_tenant(self) -> None:
        response = self.client.post(
            "/v1/billing/plan", json={"plan": "pro"}, headers=self._admin_headers
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["tenant"]["plan"], "pro")

    def test_change_plan_targets_other_tenant(self) -> None:
        # B4: платформенный админ управляет ЛЮБЫМ тенантом через tenant_id.
        self._create_tenant("acme")

        response = self.client.post(
            "/v1/billing/plan",
            json={"plan": "pro", "tenant_id": "acme"},
            headers=self._admin_headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["tenant"]["tenant_id"], "acme")
        self.assertEqual(response.json()["tenant"]["plan"], "pro")

    def test_issue_invoice_targets_other_tenant(self) -> None:
        # B4: инвойс выставляется указанному тенанту, а не тенанту админа.
        self._create_tenant("acme")

        response = self.client.post(
            "/v1/billing/invoices",
            json={"tenant_id": "acme"},
            headers=self._admin_headers,
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["invoice"]["tenant_id"], "acme")

    # --- Квоты на эндпоинтах аудита ---

    def test_free_tenant_blocked_at_quota_with_402(self) -> None:
        self._create_tenant("acme", plan="free")
        headers = self._tenant_headers("acme")

        # Free-план: 10 аудитов в месяц
        for i in range(10):
            response = self.client.post(
                "/v1/audit", json={"flow": LLM_FLOW}, headers=headers
            )
            self.assertEqual(response.status_code, 200, f"audit #{i + 1}")

        # Одиннадцатый блокируется
        response = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=headers
        )
        self.assertEqual(response.status_code, 402)
        self.assertIn("quota", response.json()["detail"].lower())

    def test_async_submit_also_blocked_at_quota(self) -> None:
        self._create_tenant("acme", plan="free")
        headers = self._tenant_headers("acme")

        optimize_flow = {
            "kind": "optimize",
            "name": "billing-optimize-flow",
            "dataset": [
                {"label": "sum", "prompt": "What is 2+2?", "expect_contains": "4"},
            ],
            "baseline": LLM_FLOW["old"],
            "candidates": [LLM_FLOW["new"]],
            "quality_floor": 0.9,
            "final_repetitions": 1,
        }

        # Исчерпываем квоту оптимизаций (1/месяц на free)
        response = self.client.post(
            "/v1/optimize", json={"flow": optimize_flow}, headers=headers
        )
        self.assertEqual(response.status_code, 202)
        audit_id = response.json()["audit_id"]

        # Использование записывается после завершения джоба — дожидаемся
        import time

        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            snapshot = self.client.get(
                f"/v1/optimize/{audit_id}", headers=headers
            ).json()
            if snapshot["status"] in ("completed", "failed"):
                break
            time.sleep(0.05)

        self.assertEqual(snapshot["status"], "completed")

        response = self.client.post(
            "/v1/optimize", json={"flow": optimize_flow}, headers=headers
        )
        self.assertEqual(response.status_code, 402)

    def test_upgrade_unblocks_quota(self) -> None:
        self._create_tenant("acme", plan="free")
        headers = self._tenant_headers("acme")

        for _ in range(10):
            self.client.post("/v1/audit", json={"flow": LLM_FLOW}, headers=headers)

        blocked = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=headers
        )
        self.assertEqual(blocked.status_code, 402)

        # Админ тенанта переводит на pro (здесь админ платформы — default;
        # меняем план тенанта напрямую через движок, как это сделал бы биллинг)
        api_module.billing_engine.set_plan("acme", "pro")

        unblocked = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=headers
        )
        self.assertEqual(unblocked.status_code, 200)

    # --- Инвойсы ---

    def test_issue_and_list_invoices(self) -> None:
        self._create_tenant("acme", plan="pro")
        headers = self._tenant_headers("acme")

        response = self.client.post(
            "/v1/billing/invoices", json={}, headers=headers
        )
        self.assertEqual(response.status_code, 403)  # только admin

        # Админ default-тенанта выставляет инвойс себе
        response = self.client.post(
            "/v1/billing/invoices", json={}, headers=self._admin_headers
        )
        self.assertEqual(response.status_code, 201)
        invoice = response.json()["invoice"]
        self.assertEqual(invoice["total_usd"], 0.0)  # default на free

        listing = self.client.get(
            "/v1/billing/invoices", headers=self._admin_headers
        ).json()
        self.assertEqual(listing["count"], 1)

    def test_invoice_idempotent_via_api(self) -> None:
        first = self.client.post(
            "/v1/billing/invoices", json={}, headers=self._admin_headers
        ).json()["invoice"]
        second = self.client.post(
            "/v1/billing/invoices", json={}, headers=self._admin_headers
        ).json()["invoice"]

        self.assertEqual(first["invoice_id"], second["invoice_id"])

    def test_invoice_invalid_period_400(self) -> None:
        response = self.client.post(
            "/v1/billing/invoices",
            json={"period": "2026-13"},
            headers=self._admin_headers,
        )
        self.assertEqual(response.status_code, 400)

    def test_invoice_tenant_isolation_via_api(self) -> None:
        self._create_tenant("acme", plan="pro")
        api_module.billing_engine.issue_invoice("acme")

        acme_invoice = api_module.billing_engine.list_invoices("acme")[0]
        acme_headers = self._tenant_headers("acme")

        # Acme видит свой инвойс
        response = self.client.get(
            f"/v1/billing/invoices/{acme_invoice.invoice_id}", headers=acme_headers
        )
        self.assertEqual(response.status_code, 200)

        # Default-тенант чужой инвойс не видит
        response = self.client.get(
            f"/v1/billing/invoices/{acme_invoice.invoice_id}",
            headers=self._admin_headers,
        )
        self.assertEqual(response.status_code, 404)

        # Список default-тенанта пуст
        listing = self.client.get(
            "/v1/billing/invoices", headers=self._admin_headers
        ).json()
        self.assertEqual(listing["count"], 0)

    def test_invoice_reflects_overage(self) -> None:
        self._create_tenant("acme", plan="pro")

        # 505 аудитов: 500 включено в Pro, 5 тарифицируются по $0.25
        for _ in range(505):
            api_module.usage_meter.record(tenant_id="acme", kind="llm_flow")

        invoice = api_module.billing_engine.issue_invoice("acme")

        # 99.0 подписка + 5 * 0.25 overage = 100.25
        self.assertEqual(invoice.total_usd, 100.25)
        self.assertEqual(len(invoice.lines), 2)


if __name__ == "__main__":
    unittest.main()
