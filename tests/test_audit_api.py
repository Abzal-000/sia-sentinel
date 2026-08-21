from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

import sentinel.api as api_module
from sentinel.api import app, rate_limiter
from sentinel.billing import BillingEngine
from sentinel.cryptographic_receipts import CryptographicReceipt, ReceiptVerifier
from sentinel.outbound_webhooks import OutboundWebhookDispatcher
from sentinel.receipt_registry import ReceiptRegistry
from sentinel.tenancy import TenantManager, UsageMeter

CODE_FLOW = {
    "kind": "code",
    "name": "api-fib-flow",
    "function_name": "fib",
    "old_code": "def fib(n):\n    if n <= 1:\n        return n\n    return fib(n - 1) + fib(n - 2)\n",
    "new_code": "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n",
    "test_suite": ["assert fib(10) == 55"],
    "args_template": [15],
    "performance_iterations": 50,
    "performance_repeat": 2,
    "pricing": {"compute_usd_per_hour": 3.6},
}

# kind=code исполняет произвольный код — через API запрещено (B1),
# доступно только в CLI с доверенным локальным вводом.

LLM_FLOW = {
    "kind": "llm_flow",
    "name": "api-router-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
        {"prompt": "Capital of France?", "expect_contains": "Paris"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 2,
}


class AuditAPITestCase(unittest.TestCase):
    """POST /v1/audit + реестр квитанций, с изоляцией хранилища."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        rate_limiter.reset()

        # Демо-логин выключен по умолчанию; тестам он нужен для JWT
        self._original_demo_login = os.environ.get("ENABLE_DEMO_LOGIN")
        os.environ["ENABLE_DEMO_LOGIN"] = "1"

        # Изолируем реестр от рабочих файлов репозитория
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

        # Аудиты гейтятся ролями admin/user: получаем JWT админа для POST-запросов
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

    def _public_key(self) -> str:
        return self.client.get("/v1/receipt-public-key").json()["public_key"]

    def test_audit_code_flow_rejected_via_api(self) -> None:
        # B1: kind=code выполняет произвольный код и запрещён в API
        response = self.client.post(
            "/v1/audit", json={"flow": CODE_FLOW}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("code", response.json()["detail"])

    def test_audit_file_keys_rejected_via_api(self) -> None:
        # B3: *_file-ключи читают файлы сервера и запрещены в API
        flow = {**LLM_FLOW, "catalog_file": "../../etc/passwd"}

        response = self.client.post(
            "/v1/audit", json={"flow": flow}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("catalog_file", response.json()["detail"])

    def test_audit_llm_flow_simulated(self) -> None:
        response = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["report"]["mode"], "simulated")
        self.assertTrue(data["report"]["claim"]["savings_verified"])

    def test_audit_invalid_flow_returns_400(self) -> None:
        broken = {**LLM_FLOW}
        broken.pop("dataset")

        response = self.client.post(
            "/v1/audit", json={"flow": broken}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("dataset", response.json()["detail"])

        response = self.client.post(
            "/v1/audit", json={"flow": {"kind": "unknown"}}, headers=self._auth_headers
        )
        self.assertEqual(response.status_code, 400)

    def test_audit_requires_auth(self) -> None:
        response = self.client.post("/v1/audit", json={"flow": LLM_FLOW})

        self.assertEqual(response.status_code, 401)

    def test_audit_rejects_insufficient_role(self) -> None:
        # verifier не входит в (admin, user) — должен получить 403
        login = self.client.post(
            "/v1/auth/login",
            json={"username": "verifier", "password": "verifier123"},
        )
        verifier_headers = {
            "Authorization": f"Bearer {login.json()['access_token']}"
        }

        response = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=verifier_headers
        )

        self.assertEqual(response.status_code, 403)

    def test_receipt_registry_endpoints(self) -> None:
        audit = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=self._auth_headers
        ).json()
        registry_id = audit["registry_id"]

        listing = self.client.get("/v1/receipts").json()
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["receipts"][0]["registry_id"], registry_id)
        self.assertEqual(listing["receipts"][0]["metadata"]["flow_name"], "api-router-flow")

        entry = self.client.get(f"/v1/receipts/{registry_id}").json()
        self.assertEqual(entry["receipt"]["evidence_id"], "audit-api-router-flow")

        verification = self.client.get(f"/v1/receipts/{registry_id}/verify").json()
        self.assertTrue(verification["valid"])
        self.assertIn("public_key", verification)

        # Квитанция проверяется публичным ключом независимо от сервера
        verifier = ReceiptVerifier(verification["public_key"])
        self.assertTrue(verifier.verify(CryptographicReceipt(**entry["receipt"])))

    def test_registry_verify_detects_tampering(self) -> None:
        audit = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=self._auth_headers
        ).json()
        registry_id = audit["registry_id"]

        registry_file = (
            Path(self._tmp.name) / "receipts" / "registry.jsonl"
        )
        entries = [
            json.loads(line)
            for line in registry_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        entries[0]["receipt"]["manifest"]["dataset_sha256"] = "forged"
        registry_file.write_text(
            "\n".join(json.dumps(entry) for entry in entries) + "\n",
            encoding="utf-8",
        )

        response = self.client.get(f"/v1/receipts/{registry_id}/verify")

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["valid"])

    def test_unknown_receipt_404(self) -> None:
        self.assertEqual(self.client.get("/v1/receipts/missing").status_code, 404)
        self.assertEqual(self.client.get("/v1/receipts/missing/verify").status_code, 404)


if __name__ == "__main__":
    unittest.main()
