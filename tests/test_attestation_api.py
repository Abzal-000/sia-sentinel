from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

import sentinel.api as api_module
from sentinel.api import app, rate_limiter
from sentinel.billing import BillingEngine
from sentinel.outbound_webhooks import OutboundWebhookDispatcher
from sentinel.receipt_registry import ReceiptRegistry
from sentinel.tenancy import TenantManager, UsageMeter

LLM_FLOW = {
    "kind": "llm_flow",
    "name": "attestation-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 1,
}


class AttestationAPITestCase(unittest.TestCase):
    """Публичные аттестации + леджер: head, verify, checkpoints, badge."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        rate_limiter.reset()

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

    def _register_audit(self) -> str:
        response = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )
        self.assertEqual(response.status_code, 200)
        return response.json()["registry_id"]

    def test_ledger_head_empty(self) -> None:
        head = self.client.get("/v1/ledger/head").json()

        self.assertEqual(head["seq"], 0)
        self.assertIsNone(head["entry_hash"])

    def test_ledger_head_after_registration(self) -> None:
        registry_id = self._register_audit()
        head = self.client.get("/v1/ledger/head").json()

        self.assertEqual(head["seq"], 1)
        self.assertEqual(head["registry_id"], registry_id)
        self.assertIsNotNone(head["entry_hash"])

    def test_ledger_verify_valid(self) -> None:
        self._register_audit()
        self._register_audit()

        result = self.client.get("/v1/ledger/verify").json()

        self.assertTrue(result["valid"])
        self.assertEqual(result["entries"], 2)
        self.assertIn("public_key", result)

    def test_checkpoint_requires_admin(self) -> None:
        self._register_audit()

        # Без авторизации
        response = self.client.post("/v1/ledger/checkpoint")
        self.assertEqual(response.status_code, 401)

        # С ролью user (не admin)
        login = self.client.post(
            "/v1/auth/login",
            json={"username": "user", "password": "user123"},
        )
        user_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        response = self.client.post("/v1/ledger/checkpoint", headers=user_headers)
        self.assertEqual(response.status_code, 403)

    def test_checkpoint_on_empty_ledger_conflict(self) -> None:
        response = self.client.post(
            "/v1/ledger/checkpoint", headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 409)

    def test_checkpoint_flow(self) -> None:
        self._register_audit()

        response = self.client.post(
            "/v1/ledger/checkpoint", headers=self._auth_headers
        )
        self.assertEqual(response.status_code, 200)

        checkpoint = response.json()["checkpoint"]
        self.assertEqual(checkpoint["seq"], 1)
        self.assertIn("signature", checkpoint)

        listing = self.client.get("/v1/ledger/checkpoints").json()
        self.assertEqual(listing["count"], 1)

    def test_public_attestation_document(self) -> None:
        registry_id = self._register_audit()

        attestation = self.client.get(f"/v1/attestations/{registry_id}").json()

        self.assertEqual(attestation["schema_version"], "1")
        self.assertEqual(attestation["attestation_id"], registry_id)
        self.assertEqual(attestation["subject"]["flow_name"], "attestation-flow")
        self.assertTrue(attestation["claim"]["savings_verified"])
        self.assertTrue(attestation["verification"]["receipt_signature_valid"])
        self.assertTrue(attestation["verification"]["ledger_chain_valid"])
        self.assertIn("public_key", attestation["issuer"])

    def test_attestation_unknown_id_404(self) -> None:
        response = self.client.get("/v1/attestations/missing")

        self.assertEqual(response.status_code, 404)

    def test_attestation_badge_svg(self) -> None:
        registry_id = self._register_audit()

        response = self.client.get(f"/v1/attestations/{registry_id}/badge.svg")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "image/svg+xml")
        self.assertIn("Proof-of-Savings", response.text)
        self.assertIn("verified", response.text)

    def test_attestation_is_public_no_auth(self) -> None:
        registry_id = self._register_audit()

        # Аттестации и леджер публичны: верификация не требует ключа
        self.assertEqual(
            self.client.get(f"/v1/attestations/{registry_id}").status_code, 200
        )
        self.assertEqual(self.client.get("/v1/ledger/verify").status_code, 200)


if __name__ == "__main__":
    unittest.main()
