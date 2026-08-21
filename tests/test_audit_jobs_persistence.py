from __future__ import annotations

import time
import unittest

from sentinel.audit_jobs import AuditJobManager
from sentinel.database import AuditJobRecord, get_db_session, init_db

FLOW = {
    "kind": "llm_flow",
    "name": "persistence-flow",
    "dataset": [{"prompt": "What is 2+2?", "expect_contains": "4"}],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 1,
}


def _fake_runner(flow: dict, tenant_id: str, audit_id: str) -> dict:
    """Лёгкий раннер: не гоняет реальный аудит, возвращает заглушку."""
    return {
        "registry_id": "fake-registry-id",
        "report": {"name": flow.get("name"), "tenant": tenant_id},
        "receipt": {"receipt_id": "fake-receipt"},
    }


def _wait_terminal(manager: AuditJobManager, audit_id: str, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        snapshot = manager.get(audit_id)

        if snapshot and snapshot["status"] in ("completed", "failed"):
            return snapshot

        time.sleep(0.05)

    raise AssertionError(f"Job {audit_id} did not finish within {timeout}s")


class AuditJobPersistenceTestCase(unittest.TestCase):
    """Джобы переживают «рестарт» (новый инстанс менеджера, та же БД)."""

    def setUp(self) -> None:
        init_db()

        with get_db_session() as db:
            db.query(AuditJobRecord).delete()

    def tearDown(self) -> None:
        with get_db_session() as db:
            db.query(AuditJobRecord).delete()

    def test_completed_job_survives_new_manager_instance(self) -> None:
        manager = AuditJobManager(_fake_runner)
        audit_id = manager.submit(FLOW, tenant_id="acme")

        snapshot = _wait_terminal(manager, audit_id)
        self.assertEqual(snapshot["status"], "completed")

        # «Рестарт»: новый инстанс видит завершённый джоб из БД
        reopened = AuditJobManager(_fake_runner)
        restored = reopened.get(audit_id)

        self.assertIsNotNone(restored)
        self.assertEqual(restored["status"], "completed")
        self.assertEqual(restored["tenant_id"], "acme")
        self.assertEqual(restored["result"]["report"]["name"], "persistence-flow")

    def test_crash_recovery_restarts_pending_job(self) -> None:
        # Имитация краха: запись создана, но воркер не успел стартовать
        with get_db_session() as db:
            db.add(AuditJobRecord(
                audit_id="crashed-pending-job",
                tenant_id="acme",
                flow_name="persistence-flow",
                status="pending",
                flow_json=dict(FLOW),
            ))

        manager = AuditJobManager(_fake_runner)
        recovered = manager.recover()

        self.assertEqual(recovered, 1)

        snapshot = _wait_terminal(manager, "crashed-pending-job")
        self.assertEqual(snapshot["status"], "completed")
        self.assertEqual(snapshot["result"]["report"]["tenant"], "acme")

    def test_crash_recovery_resets_running_job(self) -> None:
        # Имитация краха: воркер умер на середине (status=running)
        with get_db_session() as db:
            db.add(AuditJobRecord(
                audit_id="crashed-running-job",
                tenant_id="acme",
                flow_name="persistence-flow",
                status="running",
                flow_json=dict(FLOW),
            ))

        manager = AuditJobManager(_fake_runner)
        recovered = manager.recover()

        self.assertEqual(recovered, 1)

        snapshot = _wait_terminal(manager, "crashed-running-job")
        self.assertEqual(snapshot["status"], "completed")

    def test_recover_ignores_terminal_jobs(self) -> None:
        with get_db_session() as db:
            db.add(AuditJobRecord(
                audit_id="done-job",
                tenant_id="acme",
                status="completed",
                result_json={"ok": True},
            ))
            db.add(AuditJobRecord(
                audit_id="failed-job",
                tenant_id="acme",
                status="failed",
                error="boom",
            ))

        manager = AuditJobManager(_fake_runner)

        self.assertEqual(manager.recover(), 0)

    def test_tenant_isolation_survives_restart(self) -> None:
        manager = AuditJobManager(_fake_runner)
        audit_id = manager.submit(FLOW, tenant_id="acme")
        _wait_terminal(manager, audit_id)

        reopened = AuditJobManager(_fake_runner)

        self.assertIsNotNone(reopened.get(audit_id, tenant_id="acme"))
        self.assertIsNone(reopened.get(audit_id, tenant_id="globex"))

    def test_failed_runner_marks_job_failed_persistently(self) -> None:
        def broken_runner(flow: dict, tenant_id: str, audit_id: str) -> dict:
            raise RuntimeError("runner exploded")

        manager = AuditJobManager(broken_runner)
        audit_id = manager.submit(FLOW, tenant_id="acme")

        snapshot = _wait_terminal(manager, audit_id)
        self.assertEqual(snapshot["status"], "failed")
        self.assertIn("runner exploded", snapshot["error"])

        reopened = AuditJobManager(_fake_runner)
        self.assertEqual(reopened.get(audit_id)["status"], "failed")


if __name__ == "__main__":
    unittest.main()
