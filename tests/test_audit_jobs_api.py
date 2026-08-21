from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

import sentinel.api as api_module
from sentinel.api import app, rate_limiter
from sentinel.billing import BillingEngine
from sentinel.database import AuditJobRecord, get_db_session
from sentinel.outbound_webhooks import OutboundWebhookDispatcher
from sentinel.receipt_registry import ReceiptRegistry
from sentinel.tenancy import TenantManager, UsageMeter

LLM_FLOW = {
    "kind": "llm_flow",
    "name": "async-router-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 1,
}


class AuditJobsAPITestCase(unittest.TestCase):
    """POST /v1/audits + GET /v1/audits/{id}: очередь, статусы, авторизация."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        rate_limiter.reset()

        # Изолируем таблицу джобов от других тестов
        with get_db_session() as db:
            db.query(AuditJobRecord).delete()

        self._original_demo_login = os.environ.get("ENABLE_DEMO_LOGIN")
        os.environ["ENABLE_DEMO_LOGIN"] = "1"

        self._original_registry = api_module.receipt_registry
        api_module.receipt_registry = ReceiptRegistry(str(Path(self._tmp.name) / "receipts"))

        # Изолируем тенантов/учёт/биллинг: квоты не должны видеть реального usage
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

    def _wait_for_terminal_status(self, audit_id: str, timeout: float = 15.0) -> dict:
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            snapshot = self.client.get(
                f"/v1/audits/{audit_id}", headers=self._auth_headers
            ).json()

            if snapshot["status"] in ("completed", "failed"):
                return snapshot

            time.sleep(0.05)

        raise AssertionError(f"Audit {audit_id} did not finish within {timeout}s")

    def test_submit_and_poll_until_completed(self) -> None:
        response = self.client.post(
            "/v1/audits", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 202)
        audit_id = response.json()["audit_id"]
        self.assertEqual(response.json()["status"], "pending")

        snapshot = self._wait_for_terminal_status(audit_id)

        self.assertEqual(snapshot["status"], "completed")
        self.assertEqual(snapshot["flow_name"], "async-router-flow")
        self.assertIsNotNone(snapshot["started_at"])
        self.assertIsNotNone(snapshot["finished_at"])

        result = snapshot["result"]
        self.assertIn("registry_id", result)
        self.assertEqual(result["report"]["mode"], "simulated")
        self.assertTrue(result["report"]["claim"]["savings_verified"])
        self.assertIn("receipt", result)

        # Квитанция зарегистрирована и видна своему тенанту в реестре
        listing = self.client.get("/v1/receipts", headers=self._auth_headers).json()
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["receipts"][0]["registry_id"], result["registry_id"])

    def test_broken_flow_marks_job_failed(self) -> None:
        broken = {**LLM_FLOW, "dataset": []}

        response = self.client.post(
            "/v1/audits", json={"flow": broken}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 202)
        snapshot = self._wait_for_terminal_status(response.json()["audit_id"])

        self.assertEqual(snapshot["status"], "failed")
        self.assertIn("dataset", snapshot["error"])
        self.assertNotIn("result", snapshot)

    def test_unknown_flow_kind_rejected_synchronously(self) -> None:
        response = self.client.post(
            "/v1/audits",
            json={"flow": {"kind": "unknown"}},
            headers=self._auth_headers,
        )

        self.assertEqual(response.status_code, 400)

    def test_unknown_audit_id_returns_404(self) -> None:
        response = self.client.get("/v1/audits/missing", headers=self._auth_headers)

        self.assertEqual(response.status_code, 404)

    def test_submit_requires_auth(self) -> None:
        response = self.client.post("/v1/audits", json={"flow": LLM_FLOW})

        self.assertEqual(response.status_code, 401)

    def test_status_endpoint_requires_auth(self) -> None:
        response = self.client.post(
            "/v1/audits", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )
        audit_id = response.json()["audit_id"]

        # Статусы джобов приватны (тенант-изоляция): без ключа — 401
        status = self.client.get(f"/v1/audits/{audit_id}")
        self.assertEqual(status.status_code, 401)


if __name__ == "__main__":
    unittest.main()
