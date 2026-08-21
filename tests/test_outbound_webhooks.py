from __future__ import annotations

import json
import os
import tempfile
import threading
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
from sentinel.outbound_webhooks import (
    EVENT_AUDIT_COMPLETED,
    EVENT_AUDIT_FAILED,
    SIGNATURE_HEADER,
    OutboundWebhookDispatcher,
    compute_signature,
    verify_signature,
)
from sentinel.receipt_registry import ReceiptRegistry
from sentinel.tenancy import TenantManager, UsageMeter

LLM_FLOW = {
    "kind": "llm_flow",
    "name": "webhook-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 1,
}


class CapturingTransport:
    """Мок-транспорт: записывает доставки вместо похода в сеть."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self._lock = threading.Lock()

    def __call__(self, url: str, headers: dict, body: bytes) -> None:
        with self._lock:
            self.calls.append({"url": url, "headers": headers, "body": body})

    def wait_for(self, count: int, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            with self._lock:
                if len(self.calls) >= count:
                    return
            time.sleep(0.02)

        raise AssertionError(f"Expected {count} deliveries, got {len(self.calls)}")


class OutboundWebhooksUnitTestCase(unittest.TestCase):
    """Диспетчер: подписки, HMAC, изоляция, персистентность."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.file = str(Path(self._tmp.name) / "webhooks.json")
        self.transport = CapturingTransport()
        self.dispatcher = OutboundWebhookDispatcher(
            subscriptions_file=self.file, transport=self.transport
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_subscribe_validates_url(self) -> None:
        with self.assertRaises(ValueError):
            self.dispatcher.subscribe("acme", "ftp://x", [EVENT_AUDIT_COMPLETED])

    def test_subscribe_validates_events(self) -> None:
        with self.assertRaises(ValueError):
            self.dispatcher.subscribe("acme", "https://x", ["audit.exploded"])

        with self.assertRaises(ValueError):
            self.dispatcher.subscribe("acme", "https://x", [])

    def test_subscribe_generates_secret(self) -> None:
        subscription = self.dispatcher.subscribe(
            "acme", "https://example.com/hook", [EVENT_AUDIT_COMPLETED]
        )

        self.assertTrue(subscription.subscription_id.startswith("wh-"))
        self.assertEqual(len(subscription.secret), 64)

    def test_dispatch_delivers_with_valid_hmac(self) -> None:
        self.dispatcher.subscribe(
            "acme", "https://example.com/hook", [EVENT_AUDIT_COMPLETED],
            secret="test-secret",
        )

        payload = {"event": EVENT_AUDIT_COMPLETED, "audit_id": "a1", "tenant_id": "acme"}
        delivered = self.dispatcher.dispatch(EVENT_AUDIT_COMPLETED, payload)

        self.assertEqual(delivered, 1)
        self.transport.wait_for(1)

        call = self.transport.calls[0]
        self.assertEqual(call["url"], "https://example.com/hook")
        self.assertEqual(call["headers"]["X-SIA-Event"], EVENT_AUDIT_COMPLETED)
        self.assertEqual(json.loads(call["body"]), payload)

        signature = call["headers"][SIGNATURE_HEADER]
        self.assertTrue(verify_signature("test-secret", call["body"], signature))
        self.assertFalse(verify_signature("wrong-secret", call["body"], signature))

    def test_dispatch_filters_by_event(self) -> None:
        self.dispatcher.subscribe(
            "acme", "https://example.com/hook", [EVENT_AUDIT_FAILED]
        )

        delivered = self.dispatcher.dispatch(EVENT_AUDIT_COMPLETED, {"event": "x"})

        self.assertEqual(delivered, 0)
        time.sleep(0.05)
        self.assertEqual(self.transport.calls, [])

    def test_tenant_isolation(self) -> None:
        acme = self.dispatcher.subscribe(
            "acme", "https://a.example", [EVENT_AUDIT_COMPLETED]
        )
        self.dispatcher.subscribe(
            "globex", "https://g.example", [EVENT_AUDIT_COMPLETED]
        )

        self.assertEqual(len(self.dispatcher.list("acme")), 1)
        self.assertIsNone(self.dispatcher.get(acme.subscription_id, "globex"))
        self.assertFalse(self.dispatcher.unsubscribe(acme.subscription_id, "globex"))
        self.assertTrue(self.dispatcher.unsubscribe(acme.subscription_id, "acme"))

    def test_list_hides_secret(self) -> None:
        self.dispatcher.subscribe("acme", "https://a.example", [EVENT_AUDIT_COMPLETED])

        listing = self.dispatcher.list("acme")

        self.assertNotIn("secret", listing[0])

    def test_subscriptions_persist_across_instances(self) -> None:
        subscription = self.dispatcher.subscribe(
            "acme", "https://a.example", [EVENT_AUDIT_COMPLETED]
        )

        reopened = OutboundWebhookDispatcher(
            subscriptions_file=self.file, transport=self.transport
        )

        restored = reopened.get(subscription.subscription_id, "acme")
        self.assertIsNotNone(restored)
        self.assertEqual(restored.url, "https://a.example")

    def test_signature_helpers_roundtrip(self) -> None:
        body = b'{"event": "audit.completed"}'
        signature = compute_signature("s3cret", body)

        self.assertTrue(signature.startswith("sha256="))
        self.assertTrue(verify_signature("s3cret", body, signature))
        self.assertFalse(verify_signature("s3cret", body + b"x", signature))


class SSRFProtectionTestCase(unittest.TestCase):
    """D11: вебхуки не должны ходить на внутренние/служебные адреса."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.file = str(Path(self._tmp.name) / "webhooks.json")
        self.transport = CapturingTransport()
        self.dispatcher = OutboundWebhookDispatcher(
            subscriptions_file=self.file, transport=self.transport
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_forbidden_ip_literals_rejected_at_subscribe(self) -> None:
        forbidden = [
            "http://127.0.0.1/hook",          # loopback
            "http://localhost/hook",          # loopback по имени
            "http://10.0.0.1/hook",           # private
            "http://192.168.1.1/hook",        # private
            "http://172.16.0.1/hook",         # private
            "http://169.254.169.254/hook",    # cloud metadata (link-local)
            "http://0.0.0.0/hook",            # unspecified
            "http://[::1]/hook",              # IPv6 loopback
            "http://[::ffff:127.0.0.1]/hook", # IPv4-mapped IPv6 loopback
        ]

        for url in forbidden:
            with self.assertRaises(ValueError, msg=url):
                self.dispatcher.subscribe("acme", url, [EVENT_AUDIT_COMPLETED])

    def test_public_ip_literal_allowed(self) -> None:
        subscription = self.dispatcher.subscribe(
            "acme", "https://93.184.216.34/hook", [EVENT_AUDIT_COMPLETED]
        )
        self.assertIsNotNone(subscription.subscription_id)

    def test_delivery_to_forbidden_url_blocked(self) -> None:
        # Подписка создана на публичный адрес, но к моменту доставки URL
        # указывает внутрь (DNS rebinding) — доставка блокируется
        self.dispatcher._deliver("http://127.0.0.1/hook", {}, b"{}")

        time.sleep(0.05)
        self.assertEqual(self.transport.calls, [])

    def test_api_rejects_forbidden_url_with_400(self) -> None:
        from fastapi.testclient import TestClient

        from sentinel.api import app, rate_limiter

        rate_limiter.reset()

        original = api_module.webhook_dispatcher
        api_module.webhook_dispatcher = self.dispatcher

        try:
            os.environ["ENABLE_DEMO_LOGIN"] = "1"
            client = TestClient(app)
            login = client.post(
                "/v1/auth/login",
                json={"username": "admin", "password": "admin123"},
            )
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

            response = client.post(
                "/v1/webhooks/subscriptions",
                json={"url": "http://169.254.169.254/latest/meta-data/",
                      "events": ["audit.completed"]},
                headers=headers,
            )

            self.assertEqual(response.status_code, 400)
            self.assertIn("forbidden", response.json()["detail"])
        finally:
            api_module.webhook_dispatcher = original
            os.environ.pop("ENABLE_DEMO_LOGIN", None)


class OutboundWebhooksAPITestCase(unittest.TestCase):
    """Эндпоинты подписок + доставка при завершении/падении аудита."""

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

        # Диспетчер с мок-транспортом: доставки видны тесту, сети нет
        self.transport = CapturingTransport()
        self._original_webhooks = api_module.webhook_dispatcher
        api_module.webhook_dispatcher = OutboundWebhookDispatcher(
            subscriptions_file=str(Path(self._tmp.name) / "webhooks.json"),
            transport=self.transport,
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

    def _tenant_headers(self, tenant_id: str) -> dict[str, str]:
        self.client.post(
            "/v1/tenants",
            json={"name": tenant_id.title(), "tenant_id": tenant_id},
            headers=self._admin_headers,
        )
        response = self.client.post(
            "/v1/auth/api-keys",
            json={"name": f"{tenant_id}-key", "role": "user", "tenant_id": tenant_id},
            headers=self._admin_headers,
        )
        return {"X-API-Key": response.json()["api_key"]}

    def test_subscribe_returns_secret_once(self) -> None:
        response = self.client.post(
            "/v1/webhooks/subscriptions",
            json={"url": "https://example.com/hook",
                  "events": ["audit.completed"]},
            headers=self._admin_headers,
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertIn("secret", body["subscription"])
        self.assertEqual(body["subscription"]["url"], "https://example.com/hook")

        # В списке секретов нет
        listing = self.client.get(
            "/v1/webhooks/subscriptions", headers=self._admin_headers
        ).json()
        self.assertEqual(listing["count"], 1)
        self.assertNotIn("secret", listing["subscriptions"][0])

    def test_subscribe_requires_auth(self) -> None:
        response = self.client.post(
            "/v1/webhooks/subscriptions",
            json={"url": "https://example.com/hook", "events": ["audit.completed"]},
        )
        self.assertEqual(response.status_code, 401)

    def test_subscribe_invalid_400(self) -> None:
        response = self.client.post(
            "/v1/webhooks/subscriptions",
            json={"url": "not-a-url", "events": ["audit.completed"]},
            headers=self._admin_headers,
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/v1/webhooks/subscriptions",
            json={"url": "https://example.com", "events": ["audit.exploded"]},
            headers=self._admin_headers,
        )
        self.assertEqual(response.status_code, 400)

    def test_delete_subscription_tenant_isolated(self) -> None:
        acme_headers = self._tenant_headers("acme")
        globex_headers = self._tenant_headers("globex")

        created = self.client.post(
            "/v1/webhooks/subscriptions",
            json={"url": "https://example.com/hook", "events": ["audit.completed"]},
            headers=acme_headers,
        ).json()["subscription"]

        # Globex не может удалить подписку Acme
        response = self.client.delete(
            f"/v1/webhooks/subscriptions/{created['subscription_id']}",
            headers=globex_headers,
        )
        self.assertEqual(response.status_code, 404)

        # Acme может
        response = self.client.delete(
            f"/v1/webhooks/subscriptions/{created['subscription_id']}",
            headers=acme_headers,
        )
        self.assertEqual(response.status_code, 200)

    def test_completed_audit_delivers_webhook(self) -> None:
        acme_headers = self._tenant_headers("acme")

        created = self.client.post(
            "/v1/webhooks/subscriptions",
            json={"url": "https://acme.example/hook",
                  "events": ["audit.completed", "audit.failed"]},
            headers=acme_headers,
        ).json()["subscription"]

        response = self.client.post(
            "/v1/audits", json={"flow": LLM_FLOW}, headers=acme_headers
        )
        audit_id = response.json()["audit_id"]

        self.transport.wait_for(1)

        call = self.transport.calls[0]
        payload = json.loads(call["body"])

        self.assertEqual(payload["event"], "audit.completed")
        self.assertEqual(payload["audit_id"], audit_id)
        self.assertEqual(payload["tenant_id"], "acme")
        self.assertIn("registry_id", payload)

        # Подпись проверяется секретом подписки
        self.assertTrue(
            verify_signature(created["secret"], call["body"],
                             call["headers"][SIGNATURE_HEADER])
        )

    def test_failed_audit_delivers_failure_webhook(self) -> None:
        acme_headers = self._tenant_headers("acme")

        self.client.post(
            "/v1/webhooks/subscriptions",
            json={"url": "https://acme.example/hook", "events": ["audit.failed"]},
            headers=acme_headers,
        )

        broken = {**LLM_FLOW, "dataset": []}
        self.client.post("/v1/audits", json={"flow": broken}, headers=acme_headers)

        self.transport.wait_for(1)

        payload = json.loads(self.transport.calls[0]["body"])
        self.assertEqual(payload["event"], "audit.failed")
        self.assertEqual(payload["status"], "failed")
        self.assertIn("dataset", payload["error"])

    def test_no_delivery_to_other_tenant(self) -> None:
        acme_headers = self._tenant_headers("acme")
        globex_headers = self._tenant_headers("globex")

        # Подписка только у Globex
        self.client.post(
            "/v1/webhooks/subscriptions",
            json={"url": "https://globex.example/hook", "events": ["audit.completed"]},
            headers=globex_headers,
        )

        # Аудит запускает Acme — Globex не должен получить уведомление
        self.client.post("/v1/audits", json={"flow": LLM_FLOW}, headers=acme_headers)

        time.sleep(0.3)
        self.assertEqual(self.transport.calls, [])


if __name__ == "__main__":
    unittest.main()
