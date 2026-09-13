#!/usr/bin/env python3
"""Дренаж очереди асинхронных аудитов — операционная чистка БД.

Прод-урок 2026-09-07 (запись №2): воркеры аудитов — daemon-потоки, они умирают
вместе с процессом. API-старт поднимает их через recover(), но between-деплой
состояние очереди никто не видит: pending/running-записи без живого воркера
висят бесконечно, а failed-задачи без результата копятся. Этот скрипт —
одна команда оператора перед деплоем и по расписанию:

  --status   только показать (без изменений): счётчики по статусам,
             возраст старейшей pending/running, список «зомби»
  --drain    списать ВСЕ pending/running в failed («interrupted by operator
             drain») — для случаев «перед деплоем чистим всё живое»;
             completed/failed НЕ трогаются (история аудитов — не мусор)
  --prune-failed N   удалить failed-записи старше N дней (дочерний расчёт:
             created_at + N < now); по умолчанию НЕ удаляется ничего
  --dry-run  показать, что было бы сделано, не делая

Код выхода: 0 — очередь в порядке (или всё списано), 1 — есть зомби
(pending/running старше --stale-hours, по умолчанию 6), 2 — ошибка окружения.
Крон-режим: --status --stale-hours 6 → алерт при exit 1.

ЛЕДЖЕР НЕ ТРОГАЕТСЯ: задачи живут в БД аудитов (audit_jobs), подписанные
квитанции — в receipts/; этот скрипт не может изменить цепь.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import func  # noqa: E402

from sentinel.database import AuditJobRecord, get_db_session  # noqa: E402


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _fmt_age(hours: float) -> str:
    if hours < 1:
        return f"{int(hours * 60)}m"
    if hours < 48:
        return f"{hours:.1f}h"
    return f"{hours / 24:.1f}d"


def status_report(stale_hours: float) -> int:
    """Печатает состояние очереди; возвращает 1 при наличии зомби."""
    now = _utcnow()

    with get_db_session() as db:
        counts = (
            db.query(AuditJobRecord.status, func.count(AuditJobRecord.id))
            .group_by(AuditJobRecord.status)
            .all()
        )
        total = db.query(func.count(AuditJobRecord.id)).scalar() or 0

        print(f"audit queue: {total} job(s)")
        for status, n in sorted(counts):
            print(f"  {status}: {n}")

        zombies = 0
        live = (
            db.query(AuditJobRecord)
            .filter(AuditJobRecord.status.in_(["pending", "running"]))
            .all()
        )

        if live:
            oldest = min((r.created_at for r in live), default=None)
            oldest_age = _age_hours(oldest, now)

            if oldest is not None:
                print(f"  oldest pending/running: created {_fmt_age(oldest_age)} ago")

            for r in live:
                age = _age_hours(r.created_at, now)
                if age > stale_hours:
                    zombies += 1
                    print(
                        f"  ZOMBIE {r.audit_id[:12]} status={r.status} "
                        f"age={_fmt_age(age)} flow={r.flow_name!r}"
                    )

            if zombies:
                print(f"zombies: {zombies} job(s) older than {stale_hours}h "
                      f"with no live worker (daemon threads died with the process)")
                return 1

        print("queue healthy: no stale pending/running jobs")
        return 0


def _age_hours(created_at: _dt.datetime | None, now: _dt.datetime) -> float:
    if created_at is None:
        return 0.0

    created = created_at

    if created.tzinfo is None:
        created = created.replace(tzinfo=_dt.timezone.utc)

    return (now - created).total_seconds() / 3600.0


def drain(dry_run: bool) -> int:
    """Списывает все pending/running в failed — зомби не переживают деплой."""
    with get_db_session() as db:
        targets = (
            db.query(AuditJobRecord)
            .filter(AuditJobRecord.status.in_(["pending", "running"]))
            .all()
        )

        if not targets:
            print("drain: nothing to drain (no pending/running)")
            return 0

        print(f"drain: failing {len(targets)} pending/running job(s)"
              f"{' [DRY RUN]' if dry_run else ''}")

        for r in targets:
            print(f"  -> failed: {r.audit_id[:12]} ({r.status}, flow={r.flow_name!r})")

            if not dry_run:
                r.status = "failed"
                r.error = "interrupted by operator drain (scripts/drain_audit_jobs.py)"
                r.finished_at = _utcnow()

        return 0


def prune_failed(days: float, dry_run: bool) -> int:
    """Удаляет failed-записи старше N дней — очередь не пахнет."""
    cutoff = _utcnow() - _dt.timedelta(days=days)

    with get_db_session() as db:
        targets = (
            db.query(AuditJobRecord)
            .filter(
                AuditJobRecord.status == "failed",
                AuditJobRecord.created_at < cutoff.replace(tzinfo=None),
            )
            .all()
        )

        if not targets:
            print(f"prune-failed: no failed jobs older than {days}d")
            return 0

        print(f"prune-failed: deleting {len(targets)} failed job(s) older than {days}d"
              f"{' [DRY RUN]' if dry_run else ''}")

        for r in targets:
            print(f"  -> delete: {r.audit_id[:12]} flow={r.flow_name!r}")

            if not dry_run:
                db.delete(r)

        return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="drain_audit_jobs",
        description="Inspect/clean the persistent async-audit queue (audit_jobs DB).",
    )
    parser.add_argument("--status", action="store_true",
                         help="Print queue state and exit 1 if zombie jobs exist")
    parser.add_argument("--drain", action="store_true",
                         help="Fail all pending/running jobs (pre-deploy cleanup)")
    parser.add_argument("--prune-failed", type=float, metavar="DAYS", default=None,
                         help="Delete failed jobs older than DAYS")
    parser.add_argument("--stale-hours", type=float, default=6.0,
                         help="Zombie threshold for --status (default: 6)")
    parser.add_argument("--dry-run", action="store_true",
                         help="Show what would happen without writing")
    args = parser.parse_args()

    if not (args.status or args.drain or args.prune_failed is not None):
        # без флагов — показать состояние (безопасный дефолт)
        return status_report(args.stale_hours)

    exit_code = 0

    if args.status:
        exit_code = exit_code or status_report(args.stale_hours)
    if args.drain:
        exit_code = exit_code or drain(args.dry_run)
    if args.prune_failed is not None:
        exit_code = exit_code or prune_failed(args.prune_failed, args.dry_run)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
