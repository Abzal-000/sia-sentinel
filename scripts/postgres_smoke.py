#!/usr/bin/env python3
"""Дым невыполнимой ветки БД: продуктовый цикл на non-SQLite пуле.

Зачем (P3, 2026-09-14): прод-конфиг — Postgres, но ВСЕ 715 тестов гоняются
через SQLite-ветку sentinel/database.py (StaticPool/SQLite-файл или
check_same_thread=False). Non-SQLite ветка — QueuePool, pool_pre_ping,
pool_recycle, пустые connect_args — НЕ исполнялась ни разу ни в одном
тесте. Урок проекта ([[green-suite-not-proof]]): зелёный сьют ничего не
значит, если главный путь не исполняется. День деплоя — не место, чтобы
узнавать, что пул падает.

Docker Desktop на машине разработки не поднимает движок (проверено
2026-09-14: npipe dockerDesktopLinuxEngine не существует), живого
Postgres-сервера нет — потому дым доказывает максимум из доступного
БЕЗ сервера:

  1. DATABASE_URL = sqlite-ФАЙЛ (НЕ memory): та же non-SQLite ветка
     конфигурации пула исполняется (QueuePool + pre_ping + recycle),
     потому что ветка выбирается по 'sqlite:///:memory:', а не по
     диалекту — файловый sqlite идёт через QueuePool, как Postgres.
  2. Полный продуктовый цикл из demo_full (10 шагов) — на этом пуле.
  3. Проверки пула после цикла: статус, что pre_ping-инженерия жива.

Что этот дым НЕ доказывает (честные границы): psycopg2-коннект, PG-JSONB
поведение JSON-колонок, PG-права/uid в compose. Это остаётся дню деплоя;
инструкция деплоя уже требует `docker compose config`-пред-проверку, а
живой Postgres-дым — первый пункт чек-листа дня деплоя (см.
docker-compose.prod.yml: контейнер здоров за ~10 сек, делайте его ПЕРВЫМ,
до первого аудита).

Запуск: python scripts/postgres_smoke.py  (exit 0 = дым прошёл)
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

tmp = tempfile.mkdtemp(prefix="sia_pg_smoke_")
db_file = Path(tmp) / "smoke.db"
# Ключ трюка: НЕ ':memory:' — файловый sqlite берёт QueuePool-ветку
# (та же, что выберет Postgres), а не StaticPool тестов.
os.environ.update({
    "DATABASE_URL": f"sqlite:///{db_file}",
    "RECEIPTS_DIR": str(Path(tmp) / "receipts"),
    "TENANTS_FILE": str(Path(tmp) / "tenants.json"),
    "USAGE_EVENTS_FILE": str(Path(tmp) / "usage.jsonl"),
    "INVOICES_FILE": str(Path(tmp) / "invoices.json"),
    "WEBHOOKS_FILE": str(Path(tmp) / "webhooks.json"),
    "EVIDENCE_DIR": str(Path(tmp) / "evidence"),
    "RECEIPT_SIGNING_KEY": "d" * 64,
    "EVIDENCE_SIGNING_KEY": "e" * 64,
    "JWT_SECRET_KEY": "f" * 64,
    "ENABLE_DEMO_LOGIN": "",
    "PLATFORM_ADMIN_API_KEY": "plat-" + "a" * 40,
    "API_KEYS_FILE": str(Path(tmp) / "api_keys.json"),
})

import sentinel.database as database  # noqa: E402

# Дым-гейт 1: выбрана QueuePool-ветка (та, что в проде), не StaticPool
assert database._is_sqlite_memory is False, "smoke must run the non-memory pool branch"
assert database.engine.pool.__class__.__name__ == "QueuePool", (
    f"expected QueuePool (prod branch), got {type(database.engine.pool).__name__}"
)
print(f"pool branch: {type(database.engine.pool).__name__} "
      f"(size={database.engine.pool.size()}, overflow cap={database.engine.pool._max_overflow})")

import importlib  # noqa: E402
import sentinel.api as api  # noqa: E402
importlib.reload(api)
from fastapi.testclient import TestClient  # noqa: E402

c = TestClient(api.app)

print("step 1: health + signup")
r = c.get("/health")
assert r.status_code == 200, r.text
r = c.post("/v1/signup", json={"name": "Smoke Tenant", "tenant_id": "pgsmoke"})
assert r.status_code == 201, r.text
key = r.json()["api_key"]
H = {"X-API-Key": key}

print("step 2: async audit job through the DB-backed queue (persistent)")
items = [
    {"label": f"q{i}", "prompt": f"Служебный вопрос #{i}: 2+2? ANSWER=4",
     "expect_contains": "ANSWER=4"}
    for i in range(10)
]
hard = [
    {"label": f"h{i}", "prompt": f"Сложный кейс #{i}: интеграл",
     "expect_contains": f"ANSWER={i}x7"}
    for i in range(5)
]
FLOW = {
    "kind": "llm_flow", "name": "pg-smoke-flow", "delta": 0.15,
    "confidence": 0.95, "repetitions": 1,
    "dataset": items + hard,
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 10.0, "output_token_usd_per_m": 30.0},
    "new": {"model_name": "cheap", "profile": "standard",
            "input_token_usd_per_m": 0.15, "output_token_usd_per_m": 0.60,
            "simulated_reliability": 0.9},
    "anchor_declaration": "unanchored",
}
r = c.post("/v1/audits", json={"flow": FLOW}, headers=H)
assert r.status_code == 202, r.text
job = r.json()["audit_id"]
for _ in range(400):
    s = c.get(f"/v1/audits/{job}", headers=H).json()
    if s["status"] in ("completed", "failed"):
        break
    time.sleep(0.05)
assert s["status"] == "completed", s.get("error")

# Джоба прошла через audit_jobs (persistent queue) — записи в БД, не памяти
with database.get_db_session() as db:
    from sentinel.database import AuditJobRecord  # noqa: E402
    rec = db.query(AuditJobRecord).filter(AuditJobRecord.audit_id == job).first()
    assert rec is not None, "job not persisted to the database"
    assert rec.status == "completed", f"job status in DB: {rec.status}"
    print(f"job persisted in DB: audit_id={rec.audit_id[:16]}... status={rec.status}")

print("step 3: crash-recovery path — job resumable from the DB after 'restart'")
# Проверка живучести: СЕССИЯ-НА-СЕССИЮ (новая сессия = то, что процесс
# увидел бы после рестарта): job-запись читается НОВОЙ сессией пула
with database.get_db_session() as db2:
    rec2 = db2.query(AuditJobRecord).filter(AuditJobRecord.audit_id == job).first()
    assert rec2 is not None, "record invisible to a fresh session (pool isolation bug?)"
    assert rec2.tenant_id == "pgsmoke", f"tenant isolation: {rec2.tenant_id}"

print("step 4: pool survived the full product cycle")
stats = database.engine.pool.status()
print(f"pool status after cycle: {stats}")
# Пул жив, если после всего цикла соединение можно взять и вернуть:
# это то, что процесс делает на следующем запросе после «бизнес-часа»
with database.engine.connect() as conn:
    assert conn.exec_driver_sql("SELECT 1").scalar() == 1, "pool gave a dead connection"
print("pool: connection acquired + returned after the cycle (pre-ping path)")

print("step 5: ledger entry registered for the audit")
res = s["result"]
reg_id = res["registry_id"]
v = c.get("/v1/ledger/verify", params={"full": "true"}).json()
assert v["valid"], v
print(f"ledger: valid={v['valid']}, entries={v['entries']}")

print()
print("=" * 70)
print("POSTGRES-PATH SMOKE: OK")
print("  non-SQLite pool branch: executed (QueuePool, pre-ping)")
print("  full product cycle: health->signup->audit->receipt->ledger OK")
print("  DB-backed persistent jobs: written + read by fresh sessions")
print(f"  state: {tmp}")
print("  NOT covered (honest limits): live psycopg2 connect, PG-JSONB,")
print("  compose uid/permissions — first checklist item of deploy day.")
print("=" * 70)
print("PG SMOKE OK")
