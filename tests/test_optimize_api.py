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

OPTIMIZE_FLOW = {
    "kind": "optimize",
    "name": "api-optimize-flow",
    "dataset": [
        {"label": "sum", "prompt": "What is 2+2?", "expect_contains": "4"},
        {"label": "capital", "prompt": "Capital of France?", "expect_contains": "Paris"},
    ],
    "baseline": {
        "model_name": "premium-router",
        "profile": "verbose",
        "input_token_usd_per_m": 3.0,
        "output_token_usd_per_m": 15.0,
    },
    "candidates": [
        {"model_name": "economy-router", "tier": "economy",
         "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    ],
    "quality_floor": 0.9,
    "final_repetitions": 1,
}


class OptimizeAPITestCase(unittest.TestCase):
    """POST /v1/optimize + GET /v1/optimize/{id}: автоподбор конфигурации."""

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
                f"/v1/optimize/{audit_id}", headers=self._auth_headers
            ).json()

            if snapshot["status"] in ("completed", "failed"):
                return snapshot

            time.sleep(0.05)

        raise AssertionError(f"Optimization {audit_id} did not finish within {timeout}s")

    def test_submit_and_poll_optimization(self) -> None:
        response = self.client.post(
            "/v1/optimize", json={"flow": OPTIMIZE_FLOW}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 202)
        audit_id = response.json()["audit_id"]

        snapshot = self._wait_for_terminal_status(audit_id)

        self.assertEqual(snapshot["status"], "completed")

        result = snapshot["result"]
        report = result["report"]
        self.assertEqual(report["kind"], "optimize")
        self.assertEqual(report["protocol"], "proof-of-savings-optimization/1")
        self.assertEqual(report["recommendation"]["model_name"], "economy-router")
        self.assertTrue(report["recommendation"]["savings_verified"])
        self.assertIn("registry_id", result)
        self.assertIn("receipt", result)

        # Аттестация зарегистрирована в публичном реестре
        listing = self.client.get("/v1/receipts").json()
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["receipts"][0]["registry_id"], result["registry_id"])

    def test_optimize_requires_kind_optimize(self) -> None:
        llm_flow = {"kind": "llm_flow", "name": "x", "dataset": [{"prompt": "hi"}]}

        response = self.client.post(
            "/v1/optimize", json={"flow": llm_flow}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 400)

    def test_optimize_requires_auth(self) -> None:
        response = self.client.post("/v1/optimize", json={"flow": OPTIMIZE_FLOW})

        self.assertEqual(response.status_code, 401)

    def test_unknown_optimization_id_returns_404(self) -> None:
        response = self.client.get("/v1/optimize/missing", headers=self._auth_headers)

        self.assertEqual(response.status_code, 404)

    def test_broken_optimize_flow_marks_job_failed(self) -> None:
        broken = {**OPTIMIZE_FLOW, "candidates": []}

        response = self.client.post(
            "/v1/optimize", json={"flow": broken}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 202)
        snapshot = self._wait_for_terminal_status(response.json()["audit_id"])

        self.assertEqual(snapshot["status"], "failed")
        self.assertIn("candidates", snapshot["error"])


if __name__ == "__main__":
    unittest.main()
