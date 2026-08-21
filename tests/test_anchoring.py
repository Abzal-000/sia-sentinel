"""C4: внешний анкоринг чекпоинтов TrustChain."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Пакет верификатора лежит в verifier/ — добавляем в sys.path для тестов
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "verifier"))

from fastapi.testclient import TestClient

import sentinel.api as api_module
from sentinel.anchoring import (
    FileAnchorTransport,
    HttpAnchorTransport,
    publish_checkpoint,
)
from sentinel.api import app, rate_limiter
from sentinel.billing import BillingEngine
from sentinel.outbound_webhooks import OutboundWebhookDispatcher
from sentinel.receipt_registry import ReceiptRegistry
from sentinel.tenancy import TenantManager, UsageMeter


class _FakeHttpxResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


class _FakeHttpxModule:
    """Заменяет httpx внутри HttpAnchorTransport.publish."""

    def __init__(self, status_code: int = 200):
        self.status_code = status_code
        self.calls: list[dict] = []

    def post(self, url, content=None, headers=None, timeout=None):
        self.calls.append(
            {"url": url, "content": content, "headers": headers, "timeout": timeout}
        )
        return _FakeHttpxResponse(self.status_code)


class FileAnchorTransportTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.anchors_dir = str(Path(self._tmp.name) / "anchors")
        self.transport = FileAnchorTransport(self.anchors_dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _checkpoint(self, checkpoint_id: str = "cp-1") -> dict:
        return {
            "protocol": "trustchain-checkpoint/2",
            "checkpoint_id": checkpoint_id,
            "seq": 3,
            "head_hash": "a" * 64,
            "tree_size": 3,
            "root_hash": "b" * 64,
            "signature": "sig",
        }

    def test_publishes_checkpoint_json(self) -> None:
        import json

        result = self.transport.publish(self._checkpoint())

        self.assertTrue(result["ok"])
        path = Path(self.anchors_dir) / "cp-1.json"
        self.assertTrue(path.exists())

        stored = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(stored["checkpoint_id"], "cp-1")
        self.assertEqual(stored["seq"], 3)

    def test_publish_is_idempotent(self) -> None:
        checkpoint = self._checkpoint()

        first = self.transport.publish(checkpoint)
        second = self.transport.publish(checkpoint)

        self.assertTrue(first["ok"])
        self.assertTrue(second["ok"])
        self.assertIn("already anchored", second["detail"])

    def test_checkpoint_without_id_rejected(self) -> None:
        result = self.transport.publish({"seq": 1})

        self.assertFalse(result["ok"])


class HttpAnchorTransportTestCase(unittest.TestCase):
    def _inject_fake_httpx(self, fake) -> None:
        original = sys.modules.get("httpx")
        sys.modules["httpx"] = fake

        self.addCleanup(lambda: sys.modules.__setitem__("httpx", original))

    def test_posts_checkpoint_to_configured_url(self) -> None:
        fake = _FakeHttpxModule(status_code=200)
        self._inject_fake_httpx(fake)

        transport = HttpAnchorTransport(url="https://anchor.example.com/publish")
        result = transport.publish({"checkpoint_id": "cp-1", "seq": 1})

        self.assertTrue(result["ok"])
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0]["url"], "https://anchor.example.com/publish")
        self.assertEqual(fake.calls[0]["headers"]["Content-Type"], "application/json")

    def test_http_error_status_reported(self) -> None:
        self._inject_fake_httpx(_FakeHttpxModule(status_code=500))

        transport = HttpAnchorTransport(url="https://anchor.example.com/publish")
        result = transport.publish({"checkpoint_id": "cp-1"})

        self.assertFalse(result["ok"])
        self.assertIn("500", result["detail"])

    def test_ssrf_guard_rejects_internal_anchor_url(self) -> None:
        fake = _FakeHttpxModule(status_code=200)
        self._inject_fake_httpx(fake)

        transport = HttpAnchorTransport(url="http://169.254.169.254/latest/meta-data")
        result = transport.publish({"checkpoint_id": "cp-1"})

        self.assertFalse(result["ok"])
        self.assertIn("rejected", result["detail"])
        self.assertEqual(fake.calls, [])  # в сеть не ходили

    def test_missing_url_reported(self) -> None:
        transport = HttpAnchorTransport(url="")
        result = transport.publish({"checkpoint_id": "cp-1"})

        self.assertFalse(result["ok"])
        self.assertIn("ANCHOR_URL", result["detail"])


class PublishCheckpointTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_results_from_all_transports(self) -> None:
        results = publish_checkpoint(
            {"checkpoint_id": "cp-1"},
            transports=[
                FileAnchorTransport(str(Path(self._tmp.name) / "a")),
                FileAnchorTransport(str(Path(self._tmp.name) / "b")),
            ],
        )

        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["ok"] for r in results))
        self.assertEqual({r["transport"] for r in results}, {"file"})

    def test_one_failure_does_not_block_others(self) -> None:
        results = publish_checkpoint(
            {"checkpoint_id": "cp-1"},  # нет checkpoint_id? есть; плохой транспорт:
            transports=[
                _BrokenTransport(),
                FileAnchorTransport(str(Path(self._tmp.name) / "ok")),
            ],
        )

        self.assertEqual(len(results), 2)
        self.assertFalse(results[0]["ok"])
        self.assertTrue(results[1]["ok"])


class _BrokenTransport:
    name = "broken"

    def publish(self, checkpoint: dict) -> dict:
        return {"ok": False, "detail": "boom"}


class AnchorAPITestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        rate_limiter.reset()

        self._original_demo_login = os.environ.get("ENABLE_DEMO_LOGIN")
        os.environ["ENABLE_DEMO_LOGIN"] = "1"

        self._original_registry = api_module.receipt_registry
        api_module.receipt_registry = ReceiptRegistry(str(Path(self._tmp.name) / "receipts"))
        self._original_anchors_dir = os.environ.get("ANCHORS_DIR")
        os.environ["ANCHORS_DIR"] = str(Path(self._tmp.name) / "anchors")
        os.environ.pop("ANCHOR_URL", None)

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

        if self._original_anchors_dir is None:
            os.environ.pop("ANCHORS_DIR", None)
        else:
            os.environ["ANCHORS_DIR"] = self._original_anchors_dir

        if self._original_demo_login is None:
            os.environ.pop("ENABLE_DEMO_LOGIN", None)
        else:
            os.environ["ENABLE_DEMO_LOGIN"] = self._original_demo_login

        self._tmp.cleanup()

    def test_anchor_requires_admin(self) -> None:
        response = self.client.post("/v1/ledger/anchor")
        self.assertEqual(response.status_code, 401)

    def test_anchor_on_empty_ledger_conflict(self) -> None:
        response = self.client.post("/v1/ledger/anchor", headers=self._auth_headers)
        self.assertEqual(response.status_code, 409)

    def test_anchor_publishes_checkpoint_file(self) -> None:
        # Одна квитанция в реестре — есть что якорить
        from sentinel.cryptographic_receipts import ReceiptGenerator

        generator = ReceiptGenerator("anchor-test-key")
        api_module.receipt_registry.register(
            generator.generate_receipt(
                evidence_id="evidence-anchor",
                code="# code",
                safety_approved=True,
                trust_level="JUNIOR",
            )
        )

        response = self.client.post("/v1/ledger/anchor", headers=self._auth_headers)
        self.assertEqual(response.status_code, 200)

        body = response.json()
        self.assertTrue(body["anchored"])
        self.assertEqual(len(body["anchors"]), 1)
        self.assertEqual(body["anchors"][0]["transport"], "file")

        checkpoint_id = body["checkpoint"]["checkpoint_id"]
        anchored = Path(os.environ["ANCHORS_DIR"]) / f"{checkpoint_id}.json"
        self.assertTrue(anchored.exists())

        # Заякоренный чекпоинт проверяется независимым верификатором
        import json

        import sia_verifier

        published = json.loads(anchored.read_text(encoding="utf-8"))
        self.assertTrue(
            sia_verifier.verify_checkpoint(published, published["public_key"])
        )


if __name__ == "__main__":
    unittest.main()
