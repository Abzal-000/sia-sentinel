"""Регрессионные тесты мультиарендной изоляции legacy evidence-store.

ДЫРА, которую закрывает этот файл
--------------------------------
Evidence писался с tenant_id (sentinel/api.py:252), но ЧТЕНИЕ было глобальным:
`/v1/evidence`, `/v1/verifications/{id}` и `/v1/agents/{id}/history` отдавали
ВСЕ записи любому авторизованному пользователю с ролью USER — в обход всей
корректно сделанной изоляции в новых receipt/job/billing-путях. Любой tenants
мог перечислить чужую evidence. Это BOLA в мультиарендном SaaS.

Тесты ниже фиксируют: tenant-scoped чтение не выдаёт чужую evidence, а
platform-admin / VERIFIER (внешний аудитор) по-прежнему видят всё.
"""
from __future__ import annotations

import tempfile
import unittest

from sentinel.evidence_store import EvidenceStore


class EvidenceStoreTenantIsolationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = EvidenceStore(
            evidence_dir=self._tmp.name, signing_key="test-signing-key"
        )

        self.tenant_a_evidence = {
            "evidence_id": "ev-a-1",
            "agent_id": "agent-a",
            "tenant_id": "tenant-a",
            "created_at": "2026-01-01T00:00:00Z",
            "secret_field": "tenant-A-payload",
        }
        self.tenant_b_evidence = {
            "evidence_id": "ev-b-1",
            "agent_id": "agent-b",
            "tenant_id": "tenant-b",
            "created_at": "2026-01-02T00:00:00Z",
            "secret_field": "tenant-B-payload",
        }
        self.untagged_evidence = {
            "evidence_id": "ev-legacy-1",
            "agent_id": "agent-legacy",
            "created_at": "2026-01-03T00:00:00Z",
            "secret_field": "legacy-payload",
        }

        self.store.store(dict(self.tenant_a_evidence))
        self.store.store(dict(self.tenant_b_evidence))
        self.store.store(dict(self.untagged_evidence))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # --- get_by_id ---------------------------------------------------------
    def test_get_by_id_scoped_hides_other_tenant(self) -> None:
        found = self.store.get_by_id("ev-b-1", tenant_id="tenant-a")
        self.assertIsNone(found, "tenant-a must not see tenant-b evidence")

    def test_get_by_id_scoped_returns_own(self) -> None:
        found = self.store.get_by_id("ev-a-1", tenant_id="tenant-a")
        self.assertIsNotNone(found)
        self.assertEqual(found["evidence_id"], "ev-a-1")

    def test_get_by_id_unscoped_platform_admin_sees_all(self) -> None:
        # tenant_id=None -> без фильтра (platform-admin / verifier).
        self.assertIsNotNone(self.store.get_by_id("ev-a-1", tenant_id=None))
        self.assertIsNotNone(self.store.get_by_id("ev-b-1", tenant_id=None))

    def test_get_by_id_scoped_hides_untagged_legacy(self) -> None:
        # Запись без tenant_id не принадлежит ни одному тенанту и не должна
        # выдаваться tenant-scoped читателю.
        self.assertIsNone(self.store.get_by_id("ev-legacy-1", tenant_id="tenant-a"))

    # --- get_all -----------------------------------------------------------
    def test_get_all_scoped_only_own_tenant(self) -> None:
        results = self.store.get_all(tenant_id="tenant-a")
        ids = {e["evidence_id"] for e in results}
        self.assertEqual(ids, {"ev-a-1"}, "tenant-a must only see its own evidence")

    def test_get_all_scoped_tenant_b_only_own(self) -> None:
        results = self.store.get_all(tenant_id="tenant-b")
        ids = {e["evidence_id"] for e in results}
        self.assertEqual(ids, {"ev-b-1"})

    def test_get_all_unscoped_sees_everything(self) -> None:
        results = self.store.get_all(tenant_id=None)
        ids = {e["evidence_id"] for e in results}
        self.assertEqual(ids, {"ev-a-1", "ev-b-1", "ev-legacy-1"})

    # --- get_by_agent ------------------------------------------------------
    def test_get_by_agent_scoped_filters(self) -> None:
        # Один agent_id, две записи от разных тенантов.
        self.store.store(
            {
                "evidence_id": "ev-b-2",
                "agent_id": "agent-a",
                "tenant_id": "tenant-b",
                "created_at": "2026-01-04T00:00:00Z",
            }
        )
        scoped = self.store.get_by_agent("agent-a", tenant_id="tenant-a")
        ids = {e["evidence_id"] for e in scoped}
        self.assertEqual(ids, {"ev-a-1"}, "shared agent_id must not leak tenants")

    def test_get_by_agent_unscoped_sees_all(self) -> None:
        self.store.store(
            {
                "evidence_id": "ev-b-2",
                "agent_id": "agent-a",
                "tenant_id": "tenant-b",
                "created_at": "2026-01-04T00:00:00Z",
            }
        )
        unscoped = self.store.get_by_agent("agent-a", tenant_id=None)
        ids = {e["evidence_id"] for e in unscoped}
        self.assertEqual(ids, {"ev-a-1", "ev-b-2"})


class EvidenceSignatureStillWorksTestCase(unittest.TestCase):
    """Изоляция не должна ломать подпись/проверку целостности."""

    def test_store_verify_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(evidence_dir=tmp, signing_key="k")
            ev = store.store(
                {
                    "evidence_id": "x",
                    "tenant_id": "t",
                    "created_at": "2026-01-01T00:00:00Z",
                }
            )
            self.assertTrue(store.verify(ev))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
