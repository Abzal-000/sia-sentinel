from __future__ import annotations

import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

# SDK-пакет лежит в sdk/ — добавляем в sys.path для тестов
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk"))
# Пакет независимого верификатора (sia-verifier) — для independent-верификации
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "verifier"))

import uvicorn

import sentinel.api as api_module
import sentinel.auth as auth_module
from sentinel.api import app, rate_limiter
from sentinel.auth import APIKeyManager, UserRole
from sentinel.billing import BillingEngine
from sentinel.database import AuditJobRecord, get_db_session
from sentinel.outbound_webhooks import OutboundWebhookDispatcher
from sentinel.receipt_registry import ReceiptRegistry
from sentinel.tenancy import TenantManager, UsageMeter

from sia_sentinel import SentinelAPIError, SentinelClient

LLM_FLOW = {
    "kind": "llm_flow",
    "name": "sdk-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 1,
    # Правило «нет якоря — нет записи»: без объявления пререгистрация
    # отказывает (sia-preregistration/4)
    "anchor_declaration": "external-anchor",
    "anchor_reference": f"rekor:{'0' * 64}:1",
}


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class SDKTestCase(unittest.TestCase):
    """Python SDK против реального сервера (uvicorn на localhost)."""

    server: uvicorn.Server
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        config = uvicorn.Config(
            app, host="127.0.0.1", port=_free_port(), log_level="warning"
        )
        cls.server = uvicorn.Server(config)

        thread = threading.Thread(target=cls.server.run, daemon=True)
        thread.start()

        deadline = time.monotonic() + 15.0

        while not cls.server.started and time.monotonic() < deadline:
            time.sleep(0.05)

        if not cls.server.started:
            raise RuntimeError("uvicorn did not start within 15s")

        cls.base_url = f"http://127.0.0.1:{config.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.should_exit = True

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        rate_limiter.reset()

        with get_db_session() as db:
            db.query(AuditJobRecord).delete()

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

        # API-ключ с ролью admin — покрывает и аудиты, и биллинг.
        # Платформенный: биллинг-операции (issue_invoice) теперь требуют
        # привилегий платформы.
        plain_key, _ = isolated_manager.create_key(
            name="sdk-test-key", role=UserRole.ADMIN, is_platform_admin=True
        )
        self._api_key = plain_key

    def tearDown(self) -> None:
        api_module.receipt_registry = self._original_registry
        api_module.tenant_manager = self._original_tenants
        api_module.usage_meter = self._original_usage
        api_module.billing_engine = self._original_billing
        api_module.webhook_dispatcher = self._original_webhooks
        auth_module.api_key_manager = self._original_key_manager
        api_module.api_key_manager = self._original_api_key_manager
        self._tmp.cleanup()

    def _client(self) -> SentinelClient:
        return SentinelClient(self.base_url, api_key=self._api_key)

    def test_health(self) -> None:
        with self._client() as client:
            health = client.health()

        self.assertEqual(health["status"], "ok")

    def test_run_audit_sync(self) -> None:
        with self._client() as client:
            result = client.run_audit(LLM_FLOW)

        self.assertIn("registry_id", result)
        self.assertEqual(result["report"]["kind"], "llm_flow")
        self.assertTrue(result["receipt"]["safety_approved"])

    def test_async_audit_lifecycle(self) -> None:
        with self._client() as client:
            audit_id = client.submit_audit(LLM_FLOW)
            snapshot = client.wait_for_audit(audit_id, timeout=15.0, poll_interval=0.05)

        self.assertEqual(snapshot["status"], "completed")
        self.assertIn("registry_id", snapshot["result"])

    def test_failed_audit_raises(self) -> None:
        broken = {**LLM_FLOW, "dataset": []}

        with self._client() as client:
            audit_id = client.submit_audit(broken)

            with self.assertRaises(SentinelAPIError) as ctx:
                client.wait_for_audit(audit_id, timeout=15.0, poll_interval=0.05)

        self.assertIn("dataset", ctx.exception.detail)

    def test_receipts_and_ledger(self) -> None:
        with self._client() as client:
            result = client.run_audit(LLM_FLOW)
            registry_id = result["registry_id"]

            listing = client.list_receipts()
            self.assertEqual(listing["total"], 1)

            entry = client.get_receipt(registry_id)
            self.assertEqual(entry["metadata"]["flow_name"], "sdk-flow")

            head = client.ledger_head()
            self.assertEqual(head["seq"], 1)

            verification = client.verify_ledger()
            self.assertTrue(verification["valid"])

            attestation = client.get_attestation(registry_id)
            self.assertEqual(attestation["attestation_id"], registry_id)

    def test_ledger_proofs_and_key_declarations(self) -> None:
        """A6: SDK-клиент для Merkle-доказательств, tree head и ключей."""
        import os

        import sia_verifier

        original_anchors = os.environ.get("ANCHORS_DIR")
        os.environ["ANCHORS_DIR"] = str(Path(self._tmp.name) / "anchors")

        try:
            with self._client() as client:
                first = client.run_audit(LLM_FLOW)["registry_id"]
                client.run_audit(LLM_FLOW)

                head = client.ledger_head()
                self.assertEqual(head["tree_size"], 2)
                self.assertIsNotNone(head["root_hash"])

                # Inclusion proof: локальный фолд + независимый верификатор
                proof = client.inclusion_proof(first)
                self.assertEqual(proof["leaf_index"], 0)
                self.assertEqual(proof["tree_size"], 2)
                self.assertTrue(
                    sia_verifier.verify_inclusion(
                        proof["entry_hash"],
                        proof["leaf_index"],
                        proof["tree_size"],
                        proof["root_hash"],
                        proof["proof"],
                    )
                )

                # Одна строка — и запись проверена против текущего tree head
                verdict = client.verify_inclusion(first)
                self.assertTrue(verdict["included"])
                self.assertEqual(verdict["root_hash"], head["root_hash"])

                # Consistency proof: дерево размера 2 продолжает дерево размера 1
                consistency = client.consistency_proof(1, 2)
                self.assertTrue(
                    sia_verifier.verify_consistency(
                        consistency["from_size"],
                        consistency["from_root"],
                        consistency["to_size"],
                        consistency["to_root"],
                        consistency["proof"],
                    )
                )

                # Полная верификация цепочки от генезиса
                full = client.verify_ledger(full=True)
                self.assertTrue(full["valid"])
                self.assertFalse(full["incremental"])

                # Анкор пишет в цепочку генезис-декларацию активного ключа
                anchor = client.anchor_checkpoint()
                self.assertTrue(anchor["anchored"])

                # Декларации ключей: активный kid объявлен в цепочке
                keys = client.key_declarations()
                self.assertGreaterEqual(keys["count"], 1)
                declared = {d["declaration"]["kid"] for d in keys["declarations"]}
                self.assertIn(keys["active_kid"], declared)
        finally:
            if original_anchors is None:
                os.environ.pop("ANCHORS_DIR", None)
            else:
                os.environ["ANCHORS_DIR"] = original_anchors

    def test_anchor_checkpoint_via_sdk(self) -> None:
        """A6: анкоринг чекпоинта через SDK (файловый транспорт в temp)."""
        import os

        original = os.environ.get("ANCHORS_DIR")
        os.environ["ANCHORS_DIR"] = str(Path(self._tmp.name) / "anchors")

        try:
            with self._client() as client:
                client.run_audit(LLM_FLOW)
                result = client.anchor_checkpoint()

            self.assertTrue(result["anchored"])
            self.assertEqual(result["anchors"][0]["transport"], "file")
        finally:
            if original is None:
                os.environ.pop("ANCHORS_DIR", None)
            else:
                os.environ["ANCHORS_DIR"] = original

    def test_usage_and_billing(self) -> None:
        with self._client() as client:
            client.run_audit(LLM_FLOW)

            usage = client.usage()
            self.assertEqual(usage["total_events"], 1)

            plans = client.plans()
            self.assertEqual(len(plans["plans"]), 3)

            plan = client.get_plan()
            self.assertEqual(plan["plan"]["name"], "free")
            self.assertEqual(plan["quota"]["categories"]["audits"]["used"], 1)

            invoice_response = client.issue_invoice()
            invoice = invoice_response["invoice"]
            self.assertEqual(invoice["total_usd"], 0.0)  # free без overage

            listing = client.list_invoices()
            self.assertEqual(listing["count"], 1)

            fetched = client.get_invoice(invoice["invoice_id"])
            self.assertEqual(
                fetched["invoice"]["invoice_id"], invoice["invoice_id"]
            )

    def test_unauthorized_raises(self) -> None:
        with SentinelClient(self.base_url) as client:
            with self.assertRaises(SentinelAPIError) as ctx:
                client.run_audit(LLM_FLOW)

        self.assertEqual(ctx.exception.status_code, 401)

    def test_not_found_raises(self) -> None:
        with self._client() as client:
            with self.assertRaises(SentinelAPIError) as ctx:
                client.get_audit("missing-id")

        self.assertEqual(ctx.exception.status_code, 404)

    def test_verify_attestation_and_public_registry(self) -> None:
        with self._client() as client:
            result = client.run_audit(LLM_FLOW)
            registry_id = result["registry_id"]

            verdict = client.verify_attestation(registry_id)
            self.assertTrue(verdict["valid"])

            # Без opt-in публичный список пуст
            listing = client.list_public_attestations()
            self.assertEqual(listing["count"], 0)

            # Opt-in через настройки тенанта (ключ админа)
            client._post(
                "/v1/tenants/default/settings",
                json={"publish_attestations": True},
            )

            listing = client.list_public_attestations()
            self.assertEqual(listing["count"], 1)
            self.assertEqual(listing["attestations"][0]["registry_id"], registry_id)

    def test_verify_attestation_independent(self) -> None:
        """Независимая верификация локально через sia-verifier (без доверия к серверу)."""
        with self._client() as client:
            result = client.run_audit(LLM_FLOW)
            registry_id = result["registry_id"]

            verdict = client.verify_attestation_independent(registry_id)

            self.assertTrue(verdict["valid"], verdict["reasons"])
            self.assertTrue(verdict["receipt_signature_valid"])
            self.assertTrue(verdict["claim_consistent"])
            self.assertTrue(verdict["spec_recognized"])

    def test_webhook_subscription_crud(self) -> None:
        with self._client() as client:
            created = client.subscribe_webhook(
                "https://example.com/hook", ["audit.completed"]
            )
            self.assertIn("secret", created["subscription"])

            listing = client.list_webhooks()
            self.assertEqual(listing["count"], 1)
            self.assertNotIn("secret", listing["subscriptions"][0])

            deleted = client.unsubscribe_webhook(
                created["subscription"]["subscription_id"]
            )
            self.assertTrue(deleted["deleted"])

            listing = client.list_webhooks()
            self.assertEqual(listing["count"], 0)

    def test_signup_and_tenant_key_management(self) -> None:
        # Self-service регистрация без авторизации
        with SentinelClient.signup(self.base_url, "Acme Corp", tenant_id="acme") as client:
            # Ключ сразу работает
            result = client.run_audit(LLM_FLOW)
            self.assertIn("registry_id", result)

            # Админ тенанта управляет своими ключами
            created = client.create_tenant_key("acme", "ci-key", role="user")
            self.assertEqual(created["key_info"]["tenant_id"], "acme")

            listing = client.list_tenant_keys("acme")
            self.assertEqual(listing["count"], 2)

            revoked = client.revoke_tenant_key(
                "acme", created["key_info"]["key_id"]
            )
            self.assertTrue(revoked["success"])

            # Платформенные операции недоступны админу тенанта
            with self.assertRaises(SentinelAPIError) as ctx:
                client._get("/v1/tenants")
            self.assertEqual(ctx.exception.status_code, 403)

    def test_preregistration_lifecycle(self) -> None:
        # A6: SDK покрывает предрегистрацию (commitment до прогона).
        with self._client() as client:
            prereg = client.create_preregistration(LLM_FLOW)
            self.assertIn("preregistration_id", prereg)
            self.assertIn("commitment", prereg)

            prereg_id = prereg["preregistration_id"]

            fetched = client.get_preregistration(prereg_id)
            self.assertEqual(fetched["preregistration_id"], prereg_id)
            self.assertEqual(
                fetched["commitment"]["dataset_sha256"],
                prereg["commitment"]["dataset_sha256"],
            )

            # Запускаем аудит и проверяем связь предрегистрации с квитанцией
            audit = client.run_audit(LLM_FLOW)
            registry_id = audit["registry_id"]

            link = client.verify_preregistration_link(prereg_id, registry_id)
            self.assertTrue(link["valid"])
            self.assertIsNone(link["reason"])


if __name__ == "__main__":
    unittest.main()
