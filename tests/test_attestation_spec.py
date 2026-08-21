from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import jsonschema
from fastapi.testclient import TestClient

import sentinel.api as api_module
from sentinel.api import app, rate_limiter
from sentinel.billing import BillingEngine
from sentinel.outbound_webhooks import OutboundWebhookDispatcher
from sentinel.receipt_registry import ReceiptRegistry
from sentinel.tenancy import TenantManager, UsageMeter

DOCS_DIR = Path(__file__).resolve().parent.parent / "docs"

LLM_FLOW = {
    "kind": "llm_flow",
    "name": "spec-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 1,
}


class AttestationSpecTestCase(unittest.TestCase):
    """JSON Schema валидна и покрывает реальный документ аттестации."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        rate_limiter.reset()

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

    def _schema(self) -> dict:
        with open(DOCS_DIR / "attestation.schema.json", encoding="utf-8") as handle:
            return json.load(handle)

    def test_schema_file_is_valid_json_schema(self) -> None:
        schema = self._schema()
        jsonschema.Draft202012Validator.check_schema(schema)

    def test_real_attestation_passes_schema(self) -> None:
        response = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )
        self.assertEqual(response.status_code, 200)
        registry_id = response.json()["registry_id"]

        attestation = self.client.get(f"/v1/attestations/{registry_id}").json()

        jsonschema.validate(attestation, self._schema())

    def test_attestation_carries_spec_field(self) -> None:
        response = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )
        registry_id = response.json()["registry_id"]

        attestation = self.client.get(f"/v1/attestations/{registry_id}").json()

        self.assertEqual(attestation["spec"], "sia-attestation/1")
        self.assertEqual(attestation["schema_version"], "1")

    def test_tampered_attestation_fails_schema(self) -> None:
        response = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )
        registry_id = response.json()["registry_id"]

        attestation = self.client.get(f"/v1/attestations/{registry_id}").json()

        # Подделка: меняем claim — схема должна отклонить (savings_ratio не число)
        attestation["claim"]["savings_ratio"] = "99%"

        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(attestation, self._schema())


if __name__ == "__main__":
    unittest.main()
