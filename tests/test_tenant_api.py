from __future__ import annotations

import os
import tempfile
import time
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
    "name": "tenant-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 1,
}


class TenantAPITestCase(unittest.TestCase):
    """Мульти-тенантность: изоляция джобов, учёт использования, ключи."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        rate_limiter.reset()

        # Изолируем таблицу джобов от других тестов
        with get_db_session() as db:
            db.query(AuditJobRecord).delete()

        self._original_demo_login = os.environ.get("ENABLE_DEMO_LOGIN")
        os.environ["ENABLE_DEMO_LOGIN"] = "1"

        # Изолируем все состояния с файловой персистентностью
        self._original_registry = api_module.receipt_registry
        api_module.receipt_registry = ReceiptRegistry(str(Path(self._tmp.name) / "receipts"))

        self._original_tenants = api_module.tenant_manager
        api_module.tenant_manager = TenantManager(str(Path(self._tmp.name) / "tenants.json"))

        self._original_usage = api_module.usage_meter
        api_module.usage_meter = UsageMeter(str(Path(self._tmp.name) / "usage.jsonl"))

        # Биллинг-движок держит ссылки на менеджеров — изолируем и его
        # (квоты/инвойсы не должны читать рабочие файлы репозитория)
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
        # api.py импортировал имя api_key_manager в своё пространство имён —
        # подменяем в обоих модулях
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

    def _create_tenant_key(self, tenant_id: str) -> dict[str, str]:
        """Создаёт API-ключ тенанта и возвращает заголовки для запросов."""
        response = self.client.post(
            "/v1/auth/api-keys",
            json={"name": f"{tenant_id}-key", "role": "user", "tenant_id": tenant_id},
            headers=self._admin_headers,
        )
        self.assertEqual(response.status_code, 200)

        return {"X-API-Key": response.json()["api_key"]}

    def test_create_tenant_admin_only(self) -> None:
        # Без авторизации
        response = self.client.post("/v1/tenants", json={"name": "Acme"})
        self.assertEqual(response.status_code, 401)

        # С ролью user
        login = self.client.post(
            "/v1/auth/login",
            json={"username": "user", "password": "user123"},
        )
        user_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        response = self.client.post("/v1/tenants", json={"name": "Acme"}, headers=user_headers)
        self.assertEqual(response.status_code, 403)

        # Админ создаёт
        response = self.client.post(
            "/v1/tenants",
            json={"name": "Acme Corp", "tenant_id": "acme", "plan": "pro"},
            headers=self._admin_headers,
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["tenant"]["tenant_id"], "acme")

    def test_list_tenants(self) -> None:
        self.client.post(
            "/v1/tenants", json={"name": "Acme", "tenant_id": "acme"},
            headers=self._admin_headers,
        )

        listing = self.client.get("/v1/tenants", headers=self._admin_headers).json()

        ids = {t["tenant_id"] for t in listing["tenants"]}
        self.assertIn("acme", ids)
        self.assertIn("default", ids)

    def test_create_tenant_invalid_id_400(self) -> None:
        response = self.client.post(
            "/v1/tenants",
            json={"name": "Bad", "tenant_id": "UPPER CASE"},
            headers=self._admin_headers,
        )

        self.assertEqual(response.status_code, 400)

    def test_key_without_tenant_goes_default(self) -> None:
        response = self.client.post(
            "/v1/auth/api-keys",
            json={"name": "no-tenant-key", "role": "user"},
            headers=self._admin_headers,
        )

        self.assertEqual(response.json()["key_info"]["tenant_id"], "default")

    def test_job_isolation_between_tenants(self) -> None:
        self.client.post(
            "/v1/tenants", json={"name": "Acme", "tenant_id": "acme"},
            headers=self._admin_headers,
        )
        self.client.post(
            "/v1/tenants", json={"name": "Globex", "tenant_id": "globex"},
            headers=self._admin_headers,
        )

        acme_headers = self._create_tenant_key("acme")
        globex_headers = self._create_tenant_key("globex")

        # Acme отправляет асинхронный аудит
        response = self.client.post(
            "/v1/audits", json={"flow": LLM_FLOW}, headers=acme_headers
        )
        self.assertEqual(response.status_code, 202)
        audit_id = response.json()["audit_id"]

        # Acme видит свой джоб
        status = self.client.get(f"/v1/audits/{audit_id}", headers=acme_headers)
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["tenant_id"], "acme")

        # Globex не видит чужой джоб — изоляция
        status = self.client.get(f"/v1/audits/{audit_id}", headers=globex_headers)
        self.assertEqual(status.status_code, 404)

    def test_usage_summary_counts_tenant_audits(self) -> None:
        self.client.post(
            "/v1/tenants", json={"name": "Acme", "tenant_id": "acme"},
            headers=self._admin_headers,
        )
        acme_headers = self._create_tenant_key("acme")

        # Два синхронных аудита под тенантом acme
        for _ in range(2):
            response = self.client.post(
                "/v1/audit", json={"flow": LLM_FLOW}, headers=acme_headers
            )
            self.assertEqual(response.status_code, 200)

        summary = self.client.get("/v1/usage", headers=acme_headers).json()

        self.assertEqual(summary["tenant_id"], "acme")
        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["by_kind"], {"llm_flow": 2})
        self.assertEqual(summary["verified_savings_count"], 2)

        # У default-тенанта (демо-админ) свои счётчики
        default_summary = self.client.get("/v1/usage", headers=self._admin_headers).json()
        self.assertEqual(default_summary["total_events"], 0)

    def test_async_audit_records_usage_for_tenant(self) -> None:
        self.client.post(
            "/v1/tenants", json={"name": "Acme", "tenant_id": "acme"},
            headers=self._admin_headers,
        )
        acme_headers = self._create_tenant_key("acme")

        response = self.client.post(
            "/v1/audits", json={"flow": LLM_FLOW}, headers=acme_headers
        )
        audit_id = response.json()["audit_id"]

        # Дожидаемся завершения джоба
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            snapshot = self.client.get(
                f"/v1/audits/{audit_id}", headers=acme_headers
            ).json()
            if snapshot["status"] in ("completed", "failed"):
                break
            time.sleep(0.05)

        self.assertEqual(snapshot["status"], "completed")

        summary = self.client.get("/v1/usage", headers=acme_headers).json()
        self.assertEqual(summary["total_events"], 1)

    def test_receipt_metadata_carries_tenant(self) -> None:
        self.client.post(
            "/v1/tenants", json={"name": "Acme", "tenant_id": "acme"},
            headers=self._admin_headers,
        )
        acme_headers = self._create_tenant_key("acme")

        response = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=acme_headers
        )
        registry_id = response.json()["registry_id"]

        entry = self.client.get(f"/v1/receipts/{registry_id}").json()
        self.assertEqual(entry["metadata"]["tenant_id"], "acme")


if __name__ == "__main__":
    unittest.main()
