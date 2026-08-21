"""Изоляция тестового прогона (D14).

unittest импортирует пакет ``tests`` раньше любого тестового модуля, а
значит раньше первого ``import sentinel.api``. Поэтому здесь мы
перенаправляем ВСЁ файловое состояние Sentinel во временный каталог:
модульные синглтоны (receipt_registry, tenant_manager, evidence_store,
api_key_manager, ...) создаются уже на временных путях и прогон никогда
не пишет в рабочий каталог репозитория (receipts/, evidence/, *.json,
sentinel.db).

Переменные выставляются через setdefault: явно заданные извне (например,
DATABASE_URL для прогона против Postgres) имеют приоритет.
"""
from __future__ import annotations

import atexit
import os
import shutil
import tempfile

_TEST_STATE_DIR = tempfile.mkdtemp(prefix="sia_sentinel_tests_")


def _isolate_state() -> None:
    defaults = {
        "DATABASE_URL": f"sqlite:///{_TEST_STATE_DIR}/sentinel_test.db",
        "RECEIPTS_DIR": os.path.join(_TEST_STATE_DIR, "receipts"),
        "EVIDENCE_DIR": os.path.join(_TEST_STATE_DIR, "evidence"),
        "API_KEYS_FILE": os.path.join(_TEST_STATE_DIR, "api_keys.json"),
        "TENANTS_FILE": os.path.join(_TEST_STATE_DIR, "tenants.json"),
        "USAGE_EVENTS_FILE": os.path.join(_TEST_STATE_DIR, "usage_events.jsonl"),
        "INVOICES_FILE": os.path.join(_TEST_STATE_DIR, "invoices.json"),
        "WEBHOOKS_FILE": os.path.join(_TEST_STATE_DIR, "webhooks.json"),
    }

    for key, value in defaults.items():
        os.environ.setdefault(key, value)


_isolate_state()
atexit.register(shutil.rmtree, _TEST_STATE_DIR, ignore_errors=True)
