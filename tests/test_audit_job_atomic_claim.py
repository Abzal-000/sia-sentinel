"""Регрессионные тесты атомарного захвата джоба (защита от двойного выполнения).

ДЫРА, которую закрывает этот файл
--------------------------------
`_run_job` делал переход в running как «прочитал status -> если не терминальный
-> записал running». Это НЕ атомарно: два конкурентных воркера (recover() на
старте процесса против обычного submit, либо два реплика приложения) могли оба
прочитать status=pending, оба пройти проверку и оба запустить аудит. Итог —
двойной расход на LLM, две квитанции и две записи в подписанный леджер за один
job. Для продукта, где каждый аудит — подписанное доказательство и каждая
запись в леджере стоит денег, это финансово значимое и репутационное повреждение.

Тест ниже запускает N воркеров на ОДНОМ джобе и требует, чтобы runner был
вызван РОВНО ОДИН РАЗ.
"""
from __future__ import annotations

import threading
import time
import unittest

from sentinel.audit_jobs import STATUS_COMPLETED, AuditJobManager
from sentinel.database import AuditJobRecord, get_db_session, init_db


class AtomicJobClaimTestCase(unittest.TestCase):
    def setUp(self) -> None:
        init_db()
        with get_db_session() as db:
            db.query(AuditJobRecord).delete()

    def tearDown(self) -> None:
        with get_db_session() as db:
            db.query(AuditJobRecord).delete()

    def test_concurrent_workers_run_job_exactly_once(self) -> None:
        """N конкурентных воркеров на одном джобе -> runner вызван один раз."""
        calls: list[str] = []
        calls_lock = threading.Lock()

        def slow_runner(flow, tenant_id, audit_id):
            with calls_lock:
                calls.append(audit_id)
            # Задержка расширяет окно гонки между чтением и записью статуса.
            time.sleep(0.15)
            return {"ok": True, "audit_id": audit_id}

        manager = AuditJobManager(runner=slow_runner)
        # Создаём запись БЕЗ автостарта воркера, чтобы запустить гонку вручную.
        with get_db_session() as db:
            db.add(
                AuditJobRecord(
                    audit_id="race-audit-1",
                    tenant_id="t1",
                    flow_name="double-run-test",
                    status="pending",
                    created_at=__import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc
                    ),
                    flow_json={"name": "double-run-test"},
                )
            )

        threads = [
            threading.Thread(target=manager._run_job, args=("race-audit-1",))
            for _ in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(
            len(calls),
            1,
            f"job must run exactly once, ran {len(calls)} times",
        )
        self.assertEqual(manager.get("race-audit-1")["status"], STATUS_COMPLETED)

    def _make_pending_job(self, manager: AuditJobManager, audit_id: str) -> str:
        """Создаёт запись pending БЕЗ автостарта воркера.

        submit() сразу поднимает поток, который захватил бы джоб и унёс гонку
        из-под теста, поэтому для проверки CAS создаём запись напрямую.
        """
        import datetime as _dt

        with get_db_session() as db:
            db.add(
                AuditJobRecord(
                    audit_id=audit_id,
                    tenant_id="t1",
                    flow_name="cas",
                    status="pending",
                    created_at=_dt.datetime.now(_dt.timezone.utc),
                    flow_json={"name": "cas"},
                )
            )
        return audit_id

    def test_try_claim_only_succeeds_once(self) -> None:
        """Прямая проверка compare-and-swap: первый claim успешен, второй нет."""
        manager = AuditJobManager(runner=lambda f, t, a: {"ok": True})
        audit_id = self._make_pending_job(manager, "cas-job-1")

        first = manager._try_claim(audit_id)
        second = manager._try_claim(audit_id)

        self.assertTrue(first, "first claim of a pending job must succeed")
        self.assertFalse(second, "second claim must fail — job already running")

    def test_try_claim_false_for_unknown_job(self) -> None:
        manager = AuditJobManager(runner=lambda f, t, a: {"ok": True})
        self.assertFalse(manager._try_claim("does-not-exist"))

    def test_claim_does_not_reset_started_at_for_running(self) -> None:
        """Повторный claim не перезаписывает started_at у уже-running джоба."""
        manager = AuditJobManager(runner=lambda f, t, a: {"ok": True})
        audit_id = self._make_pending_job(manager, "ts-job-1")
        self.assertTrue(manager._try_claim(audit_id))

        with get_db_session() as db:
            first_started = (
                db.query(AuditJobRecord)
                .filter(AuditJobRecord.audit_id == audit_id)
                .first()
                .started_at
            )

        time.sleep(0.02)
        self.assertFalse(manager._try_claim(audit_id))

        with get_db_session() as db:
            second_started = (
                db.query(AuditJobRecord)
                .filter(AuditJobRecord.audit_id == audit_id)
                .first()
                .started_at
            )

        self.assertEqual(first_started, second_started)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
