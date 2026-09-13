"""Тесты крючка ANCHOR_AFTER_AUDIT: аудит сам фиксирует голову чекпойнтом.

Урок записи №2 (2026-09-07..13): успешный аудит оставлял голову цепи
непокрытой подписанным чекпойнтом до ближайшего ручного/кронового
якорения — шесть дней никто не видел. Крючок опционален
(ANCHOR_AFTER_AUDIT=1, по умолчанию ВЫКЛЮЧЕН), и эти тесты запирают оба
поведения: без флага — ничего не меняется; с флагом — после успешного
аудита в журнале появляется свежий чекпойнт, покрывающий новую голову.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

import sentinel.api as api_module
from sentinel.api import rate_limiter
from sentinel.receipt_registry import ReceiptRegistry

LLM_FLOW = {
    "kind": "llm_flow",
    "name": "anchor-hook-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
        {"prompt": "Capital of France?", "expect_contains": "Paris"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 1,
}


class AnchorAfterAuditTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        rate_limiter.reset()

        self._env_backup = {k: os.environ.get(k) for k in
                            ("ENABLE_DEMO_LOGIN", "ANCHOR_AFTER_AUDIT",
                             "RECEIPTS_DIR", "DATABASE_URL")}
        os.environ["ENABLE_DEMO_LOGIN"] = "1"
        os.environ.pop("ANCHOR_AFTER_AUDIT", None)

        receipts_dir = Path(self._tmp.name) / "receipts"
        os.environ["RECEIPTS_DIR"] = str(receipts_dir)
        os.environ["DATABASE_URL"] = f"sqlite:///{self._tmp.name}/jobs.db"

        self.registry = ReceiptRegistry(str(receipts_dir))
        self._original_registry = api_module.receipt_registry
        api_module.receipt_registry = self.registry

        # прочие сторы апи также уводим в tmp, как в test_audit_api
        api_module.tenant_manager = type(api_module.tenant_manager)(
            str(Path(self._tmp.name) / "tenants.json"))
        api_module.usage_meter = type(api_module.usage_meter)(
            str(Path(self._tmp.name) / "usage.jsonl"))

        self.client = TestClient(api_module.app)

        # Аудит требует авторизации — логинимся демо-админом
        login = self.client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        self._auth_headers = {
            "Authorization": f"Bearer {login.json()['access_token']}"
        }

    def tearDown(self) -> None:
        api_module.receipt_registry = self._original_registry
        rate_limiter.reset()

        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

        self._tmp.cleanup()

    def _run_audit(self) -> dict:
        response = self.client.post("/v1/audit", json={"flow": LLM_FLOW},
                                    headers=self._auth_headers)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def _checkpoint_seqs(self) -> list[int]:
        cp_file = self.registry.checkpoint_file

        if not cp_file.exists():
            return []

        import json
        return [json.loads(line)["seq"] for line in
                cp_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    def test_default_off_no_checkpoint(self) -> None:
        # БЕЗ флага поведение аудита не меняется: чекпойнтов нет.
        result = self._run_audit()
        self.assertTrue(result["registry_id"])
        self.assertEqual(self._checkpoint_seqs(), [])

    def test_flag_on_creates_covering_checkpoint(self) -> None:
        # С флагом успешный аудит сам подписывает чекпойнт, ПОКРЫВАЮЩИЙ
        # новую голову — разрыв «запись без фиксации» исчезает в момент
        # завершения аудита.
        os.environ["ANCHOR_AFTER_AUDIT"] = "1"
        self._run_audit()

        head = self.registry.head()
        self.assertIsNotNone(head)
        seqs = self._checkpoint_seqs()
        self.assertIn(head["seq"], seqs,
                      "audit completed but head is not covered by any checkpoint")


if __name__ == "__main__":
    unittest.main()
