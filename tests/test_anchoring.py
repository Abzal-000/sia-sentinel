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
    RekorAnchorTransport,
    publish_checkpoint,
)
from sentinel.api import app, rate_limiter
from sentinel.billing import BillingEngine
from sentinel.outbound_webhooks import OutboundWebhookDispatcher
from sentinel.receipt_registry import ReceiptRegistry
from sentinel.tenancy import TenantManager, UsageMeter


class _FakeHttpxResponse:
    def __init__(
        self,
        status_code: int,
        json_payload: dict | None = None,
        headers: dict | None = None,
    ):
        self.status_code = status_code
        self._json_payload = json_payload
        self.headers = headers or {}
        self.text = ""

    def json(self) -> dict:
        if self._json_payload is None:
            raise ValueError("no json payload configured")

        return self._json_payload


class _FakeHttpxModule:
    """Заменяет httpx внутри HttpAnchorTransport.publish."""

    def __init__(
        self,
        status_code: int = 200,
        json_payload: dict | None = None,
        response_headers: dict | None = None,
    ):
        self.status_code = status_code
        self._json_payload = json_payload
        self._response_headers = response_headers or {}
        self.calls: list[dict] = []
        self.gets: list[dict] = []
        # Ответ GET по умолчанию: та же полезная нагрузка, что и у POST
        self.get_status_code = 200

    def post(self, url, content=None, headers=None, timeout=None, json=None):
        self.calls.append(
            {"url": url, "content": content, "headers": headers,
             "timeout": timeout, "json": json}
        )
        return _FakeHttpxResponse(
            self.status_code, self._json_payload, self._response_headers
        )

    def get(self, url, params=None, headers=None, timeout=None):
        self.gets.append({"url": url, "params": params})
        return _FakeHttpxResponse(
            self.get_status_code,
            {params["entryUUID"]: {"logIndex": 9}} if params else {},
        )


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


class AnchorScriptTestCase(unittest.TestCase):
    """Блокер 3 мини-аудита: скрипт отказывается работать без ключа подписи."""

    def test_refuses_without_receipt_signing_key(self) -> None:
        # In-process с патчем resolve_env: guard обязан срабатывать, когда
        # ключа нет НИГДЕ (ни в окружении, ни в .env), — реальный .env теперь
        # содержит ключ, поэтому подмена на уровне модуля скрипта.
        import importlib.util
        from unittest.mock import patch

        script_path = Path(__file__).resolve().parent.parent / "scripts" / "anchor_checkpoint.py"
        spec = importlib.util.spec_from_file_location("anchor_checkpoint_test", script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with patch.object(module, "resolve_env", return_value=None):
            exit_code = module.main()

        self.assertEqual(exit_code, 3)


class RekorAnchorTransportTestCase(unittest.TestCase):
    """П.6 рецензии: публичный свидетель — hashedrekord в логе Sigstore.

    Проверено живым прогоном против rekor.sigstore.dev: Rekor верифицирует
    подпись при приёме; ветка Эд25519 требует алгоритм SHA-512 и подпись
    над сырыми байтами дайджеста; ключ передаётся base64(PEM-текст).
    """

    def _inject_fake_httpx(self, fake) -> None:
        original = sys.modules.get("httpx")
        sys.modules["httpx"] = fake

        self.addCleanup(lambda: sys.modules.__setitem__("httpx", original))

    @staticmethod
    def _checkpoint() -> dict:
        return {
            "protocol": "trustchain-checkpoint/2",
            "checkpoint_id": "cp-rk",
            "created_at": "2026-08-24T00:00:00+00:00",
            "seq": 1,
            "head_hash": "c" * 64,
            "registry_id": "reg-1",
            "tree_size": 1,
            "root_hash": "d" * 64,
            "kid": "0123456789abcdef",
            "public_key": "pk",
            "signature": "sig",
        }

    class _TestSigner:
        """Seed-подписант на sentinel.ed25519ph: подпись реально
        верифицируется verify_digest — как её проверит Rekor."""

        signed_by = "test"

        def __init__(self):
            import base64

            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
            )

            from sentinel import ed25519ph

            self._ph = ed25519ph
            self.seed = bytes(range(32))
            pub = ed25519ph.public_key(self.seed)
            pem = Ed25519PublicKey.from_public_bytes(pub).public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            )
            self.public_pem_b64 = base64.b64encode(pem).decode("ascii")

        def sign(self, digest64: bytes) -> bytes:
            return self._ph.sign_digest(self.seed, digest64)

    def test_posts_verifiable_hashedrekord(self) -> None:
        import base64
        import hashlib as hashlib_mod

        from sentinel.receipt_registry import _checkpoint_commitment

        signer = self._TestSigner()
        fake = _FakeHttpxModule(status_code=201, json_payload={"rk-1": {"logIndex": 7}})
        self._inject_fake_httpx(fake)

        checkpoint = self._checkpoint()
        transport = RekorAnchorTransport(signer=signer)
        result = transport.publish(checkpoint)

        self.assertTrue(result["ok"])
        self.assertEqual(result["rekor_uuid"], "rk-1")
        self.assertEqual(result["rekor_index"], 7)
        # Готовая строка: копируется в flow, не набирается руками
        self.assertEqual(result["anchor_reference"], "rekor:rk-1:7")

        body = fake.calls[0]["json"]
        self.assertEqual(body["apiVersion"], "0.0.1")
        self.assertEqual(body["kind"], "hashedrekord")

        spec = body["spec"]
        value = hashlib_mod.sha512(
            _checkpoint_commitment(checkpoint)
        ).digest()
        self.assertEqual(spec["data"]["hash"]["algorithm"], "sha512")
        self.assertEqual(spec["data"]["hash"]["value"], value.hex())

        # Подпись — Ed25519ph над PH(M)=value, как её примет Rekor
        content = base64.b64decode(spec["signature"]["content"])
        pub = signer._ph.public_key(signer.seed)
        self.assertTrue(signer._ph.verify_digest(pub, value, content))

        pem = base64.b64decode(spec["signature"]["publicKey"]["content"])
        self.assertIn(b"BEGIN PUBLIC KEY", pem)

    def test_conflict_recovers_index_and_reference(self) -> None:
        """Ожидаемый путь повтора: 409 c Location -> GET по entryUUID ->
        готовая строка anchor_reference, а не ok без данных для вставки."""
        uuid64 = "c" * 64
        fake = _FakeHttpxModule(
            status_code=409,
            json_payload={"code": 409, "message": "entry already exists"},
            response_headers={"Location": f"/api/v1/log/entries/{uuid64}"},
        )
        self._inject_fake_httpx(fake)

        result = RekorAnchorTransport(signer=self._TestSigner()).publish(
            self._checkpoint()
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["rekor_uuid"], uuid64)
        self.assertEqual(result["rekor_index"], 9)
        self.assertEqual(result["anchor_reference"], f"rekor:{uuid64}:9")
        self.assertEqual(fake.gets[0]["params"], {"entryUUID": uuid64})

    def test_conflict_error_body_recovers_id_from_message(self) -> None:
        """Тело 409 у Rekor — {code,message}: первый ключ НЕ UUID.
        Раньше next(iter(payload)) отдавал 'code', и путь повтора был
        тупиком; теперь идентификатор ищется по форме внутри текста."""
        error_body = {
            "code": 409,
            "message": (
                "entry already exists: "
                f"{'e' * 80}"
            ),
        }
        fake = _FakeHttpxModule(status_code=409, json_payload=error_body)
        self._inject_fake_httpx(fake)

        result = RekorAnchorTransport(signer=self._TestSigner()).publish(
            self._checkpoint()
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["rekor_uuid"], "e" * 80)
        self.assertEqual(result["anchor_reference"], f"rekor:{'e' * 80}:9")

    def test_conflict_without_recoverable_id_is_honest(self) -> None:
        """Не нашли форму нигде — ok=True, но честно 'reference unavailable',
        без выдуманного идентификатора из первого ключа ошибки."""
        fake = _FakeHttpxModule(
            status_code=409,
            json_payload={"code": 409, "message": "duplicate entry"},
        )
        fake.get_status_code = 500
        self._inject_fake_httpx(fake)

        result = RekorAnchorTransport(signer=self._TestSigner()).publish(
            self._checkpoint()
        )

        self.assertTrue(result["ok"])
        self.assertIn("reference unavailable", result["detail"])
        self.assertNotIn("anchor_reference", result)

    def test_signing_failure_reported_before_http(self) -> None:
        fake = _FakeHttpxModule(status_code=201)
        self._inject_fake_httpx(fake)

        class BrokenSigner:
            signed_by = "broken"
            public_pem_b64 = ""

            def sign(self, payload: bytes) -> bytes:
                raise RuntimeError("no key")

        result = RekorAnchorTransport(signer=BrokenSigner()).publish(
            self._checkpoint()
        )

        self.assertFalse(result["ok"])
        self.assertIn("cannot build entry", result["detail"])
        self.assertEqual(fake.calls, [])

    def test_http_error_reported_with_body(self) -> None:
        self._inject_fake_httpx(_FakeHttpxModule(status_code=500))

        transport = RekorAnchorTransport(signer=self._TestSigner())
        result = transport.publish(self._checkpoint())

        self.assertFalse(result["ok"])
        self.assertIn("500", result["detail"])

    def test_ssrf_url_rejected(self) -> None:
        transport = RekorAnchorTransport(url="http://169.254.169.254/")

        result = transport.publish(self._checkpoint())

        self.assertFalse(result["ok"])
        self.assertIn("rejected", result["detail"])

    def test_rekor_opt_in_via_env(self) -> None:
        import sentinel.anchoring as anchoring_module

        class _StubFile:
            name = "stub-file"

            def __init__(self, *args, **kwargs):
                pass

            def publish(self, checkpoint):
                return {"ok": True, "detail": ""}

        original_file = anchoring_module.FileAnchorTransport
        anchoring_module.FileAnchorTransport = _StubFile
        self.addCleanup(
            setattr, anchoring_module, "FileAnchorTransport", original_file
        )

        original_flag = os.environ.get("REKOR_ANCHOR")
        try:
            os.environ.pop("REKOR_ANCHOR", None)
            names_off = [
                r["transport"] for r in anchoring_module.publish_checkpoint({})
            ]
            os.environ["REKOR_ANCHOR"] = "1"
            names_on = [
                r["transport"] for r in anchoring_module.publish_checkpoint({})
            ]
        finally:
            if original_flag is None:
                os.environ.pop("REKOR_ANCHOR", None)
            else:
                os.environ["REKOR_ANCHOR"] = original_flag

        self.assertNotIn("rekor", names_off)
        self.assertIn("rekor", names_on)


if __name__ == "__main__":
    unittest.main()
