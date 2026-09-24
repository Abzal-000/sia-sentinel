"""Асинхронные аудиты Proof-of-Savings: персистентная очередь джобов.

Долгие аудиты (особенно live-прогоны LLM-флоу) не должны держать HTTP-запрос
открытым: клиент отправляет флоу, получает audit_id и опрашивает статус.
Состояние джобов хранится в БД (таблица audit_jobs): отправленные аудиты
переживают рестарт процесса, а прерванные крахом — перезапускаются методом
recover() по сохранённой декларации флоу.

Ограничение прототипа: recover() перезапускает live-флоу после краха, что
может привести к повторным вызовам внешних API; идемпотентность на стороне
внешних сервисов не гарантируется.
"""
from __future__ import annotations

import datetime as _dt
import threading
import uuid
from typing import Any, Callable, Optional

from .database import AuditJobRecord, get_db_session, init_db

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

_TERMINAL_STATUSES = (STATUS_COMPLETED, STATUS_FAILED)


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if value else None


def _record_to_dict(record: AuditJobRecord) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "audit_id": record.audit_id,
        "status": record.status,
        "flow_name": record.flow_name,
        "tenant_id": record.tenant_id,
        "created_at": _iso(record.created_at),
        "started_at": _iso(record.started_at),
        "finished_at": _iso(record.finished_at),
    }

    if record.status == STATUS_FAILED:
        snapshot["error"] = record.error

    if record.status == STATUS_COMPLETED:
        snapshot["result"] = record.result_json

    return snapshot


class AuditJobManager:
    """Принимает флоу, запускает аудит в фоне и отдаёт статус по audit_id.

    Состояние — в БД, поэтому джобы переживают рестарт процесса.
    """

    def __init__(
        self,
        runner: Callable[[dict[str, Any], str, str], dict[str, Any]],
        on_failure: Optional[Callable[[str, str, str], None]] = None,
    ):
        # runner: (flow, tenant_id, audit_id) -> {"registry_id", "report", "receipt"}
        # on_failure: (audit_id, tenant_id, error) — вызывается при падении джоба
        self._runner = runner
        self._on_failure = on_failure
        init_db()

    def submit(self, flow: dict[str, Any], tenant_id: str = "default") -> str:
        """Ставит аудит в очередь и сразу возвращает audit_id."""
        audit_id = uuid.uuid4().hex

        record = AuditJobRecord(
            audit_id=audit_id,
            tenant_id=tenant_id or "default",
            flow_name=flow.get("name"),
            status=STATUS_PENDING,
            created_at=_utcnow(),
            flow_json=dict(flow),
        )

        with get_db_session() as db:
            db.add(record)

        self._start_worker(audit_id)

        return audit_id

    def get(self, audit_id: str, tenant_id: Optional[str] = None) -> Optional[dict[str, Any]]:
        """Снимок состояния джоба; None — неизвестный audit_id.

        При заданном tenant_id джоб чужого тенанта тоже возвращается как
        None — изоляция: клиент не может опрашивать чужие аудиты.
        """
        with get_db_session() as db:
            record = (
                db.query(AuditJobRecord)
                .filter(AuditJobRecord.audit_id == audit_id)
                .first()
            )

            if record is None:
                return None

            if tenant_id is not None and record.tenant_id != tenant_id:
                return None

            return _record_to_dict(record)

    def count(self) -> int:
        with get_db_session() as db:
            return db.query(AuditJobRecord).count()

    def recover(self) -> int:
        """Перезапускает джобы, прерванные крахом/рестартом процесса.

        running -> pending (воркер умер на середине), затем все
        pending/running перезапускаются по сохранённому flow_json.
        Возвращает число перезапущенных джобов.
        """
        with get_db_session() as db:
            interrupted = (
                db.query(AuditJobRecord)
                .filter(AuditJobRecord.status.in_([STATUS_PENDING, STATUS_RUNNING]))
                .all()
            )

            audit_ids = []

            for record in interrupted:
                record.status = STATUS_PENDING
                record.started_at = None
                audit_ids.append(record.audit_id)

        for audit_id in audit_ids:
            self._start_worker(audit_id)

        return len(audit_ids)

    # === Внутреннее ===

    def _try_claim(self, audit_id: str) -> bool:
        """Атомарно переводит джоб pending -> running. True — захват наш.

        Джоб, уже находящийся в running/completed/failed, не перезаписывается:
        условие ``status = pending`` делает захват эксклюзивным даже при гонке
        нескольких воркеров (recover() против обычного submit, два реплики
        приложения). Возвращает False, если джоб уже не pending или не найден.
        """
        with get_db_session() as db:
            updated = (
                db.query(AuditJobRecord)
                .filter(
                    AuditJobRecord.audit_id == audit_id,
                    AuditJobRecord.status == STATUS_PENDING,
                )
                .update(
                    {AuditJobRecord.status: STATUS_RUNNING,
                     AuditJobRecord.started_at: _utcnow()},
                    synchronize_session=False,
                )
            )
            return updated == 1

    def _start_worker(self, audit_id: str) -> None:
        worker = threading.Thread(
            target=self._run_job,
            args=(audit_id,),
            name=f"audit-job-{audit_id[:8]}",
            daemon=True,
        )
        worker.start()

    def _run_job(self, audit_id: str) -> None:
        # Атомарный захват джоба: UPDATE ... WHERE status='pending' + проверка
        # rowcount — это compare-and-swap на уровне БД.
        #
        # Раньше переход делался как «прочитал status -> если не терминальный ->
        # записал running». Между чтением и записью другой воркер (recover() на
        # старте, второй инстанс приложения) мог прочитать тот же pending и
        # тоже запустить аудит. Итог — двойной расход на LLM, две квитанции и
        # две записи в леджере за один job. Теперь захват атомарен: обновление
        # сработает ровно у одного воркера, второй увидит rowcount=0 и выйдет.
        claimed = self._try_claim(audit_id)
        if not claimed:
            return

        with get_db_session() as db:
            record = (
                db.query(AuditJobRecord)
                .filter(AuditJobRecord.audit_id == audit_id)
                .first()
            )
            if record is None:
                return
            flow = dict(record.flow_json or {})
            tenant_id = record.tenant_id

        try:
            result = self._runner(flow, tenant_id, audit_id)
        except Exception as exc:  # воркер не должен падать молча
            with get_db_session() as db:
                record = (
                    db.query(AuditJobRecord)
                    .filter(AuditJobRecord.audit_id == audit_id)
                    .first()
                )

                if record is not None:
                    record.status = STATUS_FAILED
                    record.error = str(exc)
                    record.finished_at = _utcnow()

            if self._on_failure is not None:
                try:
                    self._on_failure(audit_id, tenant_id, str(exc))
                except Exception:  # уведомление не должно ронять воркер
                    pass

            return

        with get_db_session() as db:
            record = (
                db.query(AuditJobRecord)
                .filter(AuditJobRecord.audit_id == audit_id)
                .first()
            )

            if record is not None:
                record.status = STATUS_COMPLETED
                record.result_json = result
                record.finished_at = _utcnow()
