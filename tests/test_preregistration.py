"""Тесты предрегистрации: обязательство аудита коммитится в цепочку ДО прогона."""
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
    "name": "prereg-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
        {"prompt": "Capital of France?", "expect_contains": "Paris"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "delta": 0.10,
    "repetitions": 1,
    # Правило «нет якоря — нет записи» в коде: без явного объявления
    # пререгистрация отказывает; external-anchor требует проверяемой ссылки
    "anchor_declaration": "external-anchor",
    # Форма инстанса: 64 hex без дефисов (или 80 — шардированный ID)
    "anchor_reference": f"rekor:{'0' * 64}:1",
}


class PreregistrationAPITestCase(unittest.TestCase):
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

    def test_create_preregistration(self) -> None:
        response = self.client.post(
            "/v1/preregistrations", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("preregistration_id", data)
        commitment = data["commitment"]
        self.assertEqual(commitment["protocol"], "sia-preregistration/4")
        self.assertEqual(commitment["delta"], 0.10)
        self.assertEqual(commitment["metric"], "expect_contains/digit-anchored")
        # Раскрытие допуска реплея: дефолт из измерения воспроизводимости
        self.assertEqual(commitment["replay_tolerance"], 0.05)
        # Направленное правило учёта допуска (с /2): порог на односторонней
        # доле «к заявлению»
        self.assertEqual(
            commitment["replay_tolerance_rule"],
            "directional-one-sided:toward-claim",
        )
        # Явное признание статуса якоря замораживается в леджере
        self.assertEqual(commitment["anchor_declaration"], "external-anchor")
        self.assertEqual(
            commitment["anchor_reference"], f"rekor:{'0' * 64}:1"
        )
        self.assertEqual(commitment["dataset_size"], 2)
        self.assertIn("dataset_sha256", commitment)

    def test_preregistration_without_anchor_declaration_refused(self) -> None:
        """Правило в коде, не в памяти: молча пройти без объявления нельзя."""
        flow_without_anchor = {k: v for k, v in LLM_FLOW.items() if k != "anchor_declaration"}

        response = self.client.post(
            "/v1/preregistrations",
            json={"flow": flow_without_anchor},
            headers=self._auth_headers,
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("anchor_declaration", response.text)

    def test_external_anchor_without_reference_refused(self) -> None:
        """external-anchor без проверяемого идентификатора — слово, не proof."""
        bare = {k: v for k, v in LLM_FLOW.items() if k != "anchor_reference"}

        response = self.client.post(
            "/v1/preregistrations", json={"flow": bare}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("anchor_reference", response.text)

    def test_external_anchor_with_malformed_reference_refused(self) -> None:
        """Голый дайджест без префикса и dashed-UUID отвергаются: форма
        обязана быть самоописывающей, entry-id — как отдаёт инстанс."""
        malformed = dict(LLM_FLOW)
        malformed["anchor_reference"] = "a" * 64

        response = self.client.post(
            "/v1/preregistrations",
            json={"flow": malformed},
            headers=self._auth_headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("anchor_reference", response.text)

        dashed = dict(LLM_FLOW)
        dashed["anchor_reference"] = "rekor:00000000-0000-0000-0000-000000000000:1"

        response = self.client.post(
            "/v1/preregistrations",
            json={"flow": dashed},
            headers=self._auth_headers,
        )
        self.assertEqual(response.status_code, 400)

    def test_rfc3161_reference_accepted(self) -> None:
        """Вторая самописующая форма: rfc3161:<64hex>."""
        tsa = dict(LLM_FLOW)
        tsa["anchor_reference"] = f"rfc3161:{'b' * 64}"

        response = self.client.post(
            "/v1/preregistrations", json={"flow": tsa}, headers=self._auth_headers
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["commitment"]["anchor_reference"],
            f"rfc3161:{'b' * 64}",
        )

    def test_unanchored_needs_no_reference(self) -> None:
        """Признание 'unanchored' — не претензия; ссылка ему не нужна."""
        confession = dict(LLM_FLOW)
        confession["anchor_declaration"] = "unanchored"
        del confession["anchor_reference"]

        response = self.client.post(
            "/v1/preregistrations",
            json={"flow": confession},
            headers=self._auth_headers,
        )

        self.assertEqual(response.status_code, 200)
        commitment = response.json()["commitment"]
        self.assertEqual(commitment["anchor_declaration"], "unanchored")
        self.assertIsNone(commitment["anchor_reference"])

    def test_preregistration_requires_auth(self) -> None:
        response = self.client.post("/v1/preregistrations", json={"flow": LLM_FLOW})
        self.assertEqual(response.status_code, 401)

    def test_get_preregistration(self) -> None:
        created = self.client.post(
            "/v1/preregistrations", json={"flow": LLM_FLOW}, headers=self._auth_headers
        ).json()

        fetched = self.client.get(
            f"/v1/preregistrations/{created['preregistration_id']}"
        ).json()

        self.assertEqual(fetched["preregistration_id"], created["preregistration_id"])
        self.assertEqual(fetched["commitment"]["delta"], 0.10)

    def test_get_missing_preregistration_404(self) -> None:
        response = self.client.get("/v1/preregistrations/nonexistent")
        self.assertEqual(response.status_code, 404)

    def test_preregistration_matches_audit(self) -> None:
        """Полный цикл: предрегистрация -> аудит -> проверка связи."""
        created = self.client.post(
            "/v1/preregistrations", json={"flow": LLM_FLOW}, headers=self._auth_headers
        ).json()
        prereg_id = created["preregistration_id"]

        audit = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=self._auth_headers
        ).json()
        registry_id = audit["registry_id"]

        link = self.client.get(
            f"/v1/preregistrations/{prereg_id}/verify/{registry_id}"
        ).json()

        self.assertTrue(link["valid"], link.get("reason"))

    def test_preregistration_mismatch_detected(self) -> None:
        """Аудит с другим датасетом не проходит проверку предрегистрации."""
        created = self.client.post(
            "/v1/preregistrations", json={"flow": LLM_FLOW}, headers=self._auth_headers
        ).json()
        prereg_id = created["preregistration_id"]

        # Аудит с изменённым датасетом
        tampered_flow = dict(LLM_FLOW)
        tampered_flow["dataset"] = [
            {"prompt": "Different question?", "expect_contains": "x"},
        ]
        audit = self.client.post(
            "/v1/audit", json={"flow": tampered_flow}, headers=self._auth_headers
        ).json()
        registry_id = audit["registry_id"]

        link = self.client.get(
            f"/v1/preregistrations/{prereg_id}/verify/{registry_id}"
        ).json()

        self.assertFalse(link["valid"])
        self.assertIn("dataset_sha256", link["reason"])

    def test_preregistration_must_precede_receipt(self) -> None:
        """Предрегистрация ПОСЛЕ аудита не проходит проверку порядка."""
        audit = self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=self._auth_headers
        ).json()
        registry_id = audit["registry_id"]

        created = self.client.post(
            "/v1/preregistrations", json={"flow": LLM_FLOW}, headers=self._auth_headers
        ).json()
        prereg_id = created["preregistration_id"]

        link = self.client.get(
            f"/v1/preregistrations/{prereg_id}/verify/{registry_id}"
        ).json()

        self.assertFalse(link["valid"])
        self.assertIn("precede", link["reason"])

    def test_preregistration_not_in_receipt_listing(self) -> None:
        """Записи предрегистрации не попадают в список квитанций."""
        self.client.post(
            "/v1/preregistrations", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )
        self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )

        listing = self.client.get("/v1/receipts", headers=self._auth_headers).json()
        self.assertEqual(listing["total"], 1)

    def test_chain_valid_with_preregistration(self) -> None:
        """Хеш-цепочка остаётся валидной с записями предрегистрации."""
        self.client.post(
            "/v1/preregistrations", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )
        self.client.post(
            "/v1/audit", json={"flow": LLM_FLOW}, headers=self._auth_headers
        )

        chain = self.client.get("/v1/ledger/verify").json()
        self.assertTrue(chain["valid"])
        self.assertEqual(chain["entries"], 2)


class ReplayToleranceTestCase(unittest.TestCase):
    """Раскрытие допуска реплея: предрегистрировано до прогона."""

    def test_commitment_carries_protocol_v2_and_directional_rule(self) -> None:
        from sia.flow_runner import build_preregistration_commitment

        flow = {
            "kind": "llm_flow",
            "dataset": [{"prompt": "2+2?", "expect_contains": "4"}],
            "old": {"model_name": "old"},
            "new": {"model_name": "new"},
            "anchor_declaration": "unanchored",
        }

        commitment = build_preregistration_commitment(flow)

        self.assertEqual(commitment["protocol"], "sia-preregistration/4")
        self.assertEqual(commitment["replay_tolerance"], 0.05)
        self.assertEqual(
            commitment["replay_tolerance_rule"],
            "directional-one-sided:toward-claim",
        )
        # Прямой вызов с объявлением несёт его в обязательстве; отказ без
        # объявления проверяет соседний тест
        self.assertEqual(commitment["anchor_declaration"], "unanchored")

    def test_flow_without_anchor_declaration_refused(self) -> None:
        from sia.flow_runner import build_preregistration_commitment

        flow = {
            "kind": "llm_flow",
            "dataset": [{"prompt": "2+2?", "expect_contains": "4"}],
            "old": {"model_name": "old"},
            "new": {"model_name": "new"},
        }

        with self.assertRaises(ValueError) as ctx:
            build_preregistration_commitment(flow)

        self.assertIn("anchor_declaration", str(ctx.exception))

    def test_flow_key_overrides_default(self) -> None:
        from sia.flow_runner import build_preregistration_commitment

        flow = {
            "kind": "llm_flow",
            "dataset": [{"prompt": "2+2?", "expect_contains": "4"}],
            "old": {"model_name": "old"},
            "new": {"model_name": "new"},
            "replay_tolerance": 0.08,
            "anchor_declaration": "external-anchor",
            "anchor_reference": f"rekor:{'0' * 64}:1",
        }

        commitment = build_preregistration_commitment(flow)

        self.assertEqual(commitment["replay_tolerance"], 0.08)

    def test_invalid_tolerance_rejected(self) -> None:
        from sia.flow_runner import build_preregistration_commitment

        for bad in (0.0, 1.0, -0.1, "abc"):
            flow = {
                "kind": "llm_flow",
                "dataset": [{"prompt": "2+2?", "expect_contains": "4"}],
                "old": {"model_name": "old"},
                "new": {"model_name": "new"},
                "replay_tolerance": bad,
            }

            with self.assertRaises(ValueError, msg=bad):
                build_preregistration_commitment(flow)


if __name__ == "__main__":
    unittest.main()
