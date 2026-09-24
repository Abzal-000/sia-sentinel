#!/usr/bin/env python3
"""ПИТЧ-ДЕМО «ПРОДАВЕЦ ЛЖЁТ»: одна атака подлога — три строки отпора.

Сцена для инвестора/клиента: вендор ИИ-оптимизации приносит финопс-команде
квитанцию «ваша новая модель не хуже и на 99% дешевле». Финопс не верит
на слово — прогоняет аттестацию через sia-verifier. Подлог вскрывается,
живая экономия остаётся живой. Всё изолировано (tmp-состояние),
simulated-режим, криптоконтур настоящий — как в scripts/demo_full.py.

Три акта:
  1. ЧЕСТНАЯ запись: реальный аудит -> подписанная квитанция -> верификатор VALID.
  2. ПОДЛОГ: вендор рисует цифры (savings 99%, safety_approved) ПОД старой
     подписью и подменяет содержимое отчёта — то, что реально делают в
     спредшитах и PDF.
  3. ПОДСУДИМОСТЬ: sia-verifier ловит КАЖДЫЙ канал подлога; честная
     запись остаётся VALID — протокол отличает правду от лжи без доверия
     к оператору.

Запуск: ./venv/Scripts/python.exe scripts/demo_forgery.py
"""
from __future__ import annotations

import copy
import os
import sys
import tempfile
import time
from pathlib import Path

# Демо рисует рамки (── │ ┌ └) и кириллицу. На Windows-консоли с кодировкой
# cp1251 это падало UnicodeEncodeError: консоль не умеет эти символы, и скрипт
# (который CI обязан гонять) выходил с кодом 1. Переиспользуем штатный
# помощник проекта — он пере-оборачивает реальный TTY в UTF-8 с
# errors="replace", так что вывод остаётся читаемым в любой консоли.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sia.cli import _ensure_utf8_console  # noqa: E402

_ensure_utf8_console()

tmp = tempfile.mkdtemp(prefix="sia_forgery_demo_")
os.environ.update({
    "RECEIPTS_DIR": str(Path(tmp) / "receipts"),
    "TENANTS_FILE": str(Path(tmp) / "tenants.json"),
    "USAGE_EVENTS_FILE": str(Path(tmp) / "usage.jsonl"),
    "INVOICES_FILE": str(Path(tmp) / "invoices.json"),
    "WEBHOOKS_FILE": str(Path(tmp) / "webhooks.json"),
    "EVIDENCE_DIR": str(Path(tmp) / "evidence"),
    "DATABASE_URL": f"sqlite:///{Path(tmp) / 'demo.db'}",
    "RECEIPT_SIGNING_KEY": "d" * 64,
    "JWT_SECRET_KEY": "e" * 64,
    "ENABLE_DEMO_LOGIN": "",
    "PLATFORM_ADMIN_API_KEY": "plat-" + "a" * 40,
    # Глобальный стор ключей — тоже в tmp (репозиторийный api_keys.json
    # накопил ключи тестовых прогонов и пропускает бутстрап админа).
    "API_KEYS_FILE": str(Path(tmp) / "api_keys.json"),
})
# Запуск из любого cwd: корень репо в sys.path ДО импорта sentinel
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import importlib  # noqa: E402
import sentinel.api as api  # noqa: E402
importlib.reload(api)
from fastapi.testclient import TestClient  # noqa: E402

c = TestClient(api.app)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "verifier"))
from sia_verifier.core import verify_attestation  # noqa: E402
from sia_verifier.rederive import rederive  # noqa: E402


def step(n, title):
    print(f"\n{'='*70}\nАКТ {n}. {title}\n{'='*70}")


# ============================================================ АКТ 1: ЧЕСТНО
step(1, "Вендор принёс ЧЕСТНУЮ квитанцию (контрольная группа)")

r = c.post("/v1/signup", json={"name": "ФинОпс ТОО", "tenant_id": "finops"})
assert r.status_code == 201, r.text
key = r.json()["api_key"]
H = {"X-API-Key": key}

dataset = [
    {"label": f"q{i}", "prompt": f"Служебный вопрос #{i}: 2+2? ANSWER=4",
     "expect_contains": "ANSWER=4"}
    for i in range(30)
] + [
    {"label": f"hard{i}", "prompt": f"Сложный кейс #{i}: интеграл по контуру ANSWER={i}x7",
     "expect_contains": f"ANSWER={i}x7"}
    for i in range(10)
]

FLOW = {
    "kind": "llm_flow", "name": "support-bot-switch",
    "delta": 0.15, "confidence": 0.95, "repetitions": 1,
    "dataset": dataset,
    "old": {"model_name": "gpt4-premium", "profile": "verbose",
            "input_token_usd_per_m": 10.0, "output_token_usd_per_m": 30.0},
    "new": {"model_name": "mini-8b", "profile": "standard",
            "input_token_usd_per_m": 0.15, "output_token_usd_per_m": 0.60},
    "anchor_declaration": "unanchored",
}
r = c.post("/v1/audits", json={"flow": FLOW}, headers=H)
assert r.status_code == 202, r.text
job = r.json()["audit_id"]
for _ in range(300):
    s = c.get(f"/v1/audits/{job}", headers=H).json()
    if s["status"] in ("completed", "failed"):
        break
    time.sleep(0.05)
assert s["status"] == "completed", s.get("error")

res = s["result"]
honest_att = c.get(f"/v1/attestations/{res['registry_id']}").json()
honest_report = res["report"]
print(f"  честная экономия: {honest_att['claim']['savings_ratio']*100:.1f}%")
print(f"  честный вердикт: non_inferior={honest_att['claim']['paired']['non_inferior']}")

v = verify_attestation(honest_att)
print(f"  sia-verifier: valid={v.valid}  (контрольная группа зелёная)")
assert v.valid

# ============================================================ АКТ 2: ПОДЛОГ
step(2, "Конкурент-мошенник рисует цифры ПОД ЧУЖОЙ ПОДПИСЬЮ")

forged_savings = copy.deepcopy(honest_att)
forged_savings["claim"]["savings_ratio"] = 0.99
forged_savings["claim"]["savings_verified"] = True

forged_claim = copy.deepcopy(honest_att)
forged_claim["receipt"]["safety_approved"] = True
forged_claim["receipt"]["manifest"]["dataset_sha256"] = "f" * 64

forged_id = copy.deepcopy(honest_att)
forged_id["receipt"]["receipt_id"] = "e" * 64

print("  подделка №1: savings_ratio поднят до 99% (подпись НЕ тронута)")
print("  подделка №2: safety_approved=True + фейковый манифест в подписанном поле")
print("  подделка №3: перенос подписи на ДРУГУЮ квитанцию (receipt_id подменён)")

# ============================================================ АКТ 3: СУД
step(3, "ФинОпс прогоняет ВСЁ через sia-verifier (подпись/цепь) + sia-rederive (числа)")

rows = []
for name, doc, expect_valid in (
    ("честная запись", honest_att, True),
    ("подделка №2 (подмена манифеста)", forged_claim, False),
    ("подделка №3 (чужой receipt_id)", forged_id, False),
):
    verdict = verify_attestation(doc)
    ok = verdict.valid == expect_valid
    rows.append((name, ok))
    mark = "VALID (контрольная группа)" if expect_valid else (
        "ПОЙМАНА" if not verdict.valid else "!!! ПРОПУЩЕНА !!!")
    print(f"  [sia-verifier]  {name:33s} -> {mark}")
    if not verdict.valid and verdict.reasons:
        print(f"      причина: {verdict.reasons[0][:80]}")

# Подделка №1 — тоньше: подписанная часть НЕ тронута, изменена только
# НЕПОДПИСАННАЯ проекция цифры. Одного sia-verifier недостаточно — но
# ровно на это есть sia-rederive: он пересчитывает числа из отчёта,
# пришитого к подписи через code_hash, и сверяет проекцию аттестации
# (проверка №10). Так работает реальный outsider: ОБА инструмента.
print()
for name, doc in (
    ("честная запись", honest_att),
    ("подделка №1 (экономия 99%)", forged_savings),
):
    r = rederive(doc, honest_report, FLOW, chain=None, check_rekor=False)
    expect = name.startswith("честная")
    ok = r["rederived"] == expect
    rows.append((name, ok))
    mark = "REDERIVED (контрольная группа)" if expect else (
        "ПОЙМАНА" if not r["rederived"] else "!!! ПРОПУЩЕНА !!!")
    print(f"  [sia-rederive]  {name:33s} -> {mark}")
    if not r["rederived"]:
        caught = [f for f in r["failures"] if "attestation" in f or "savings" in f]
        if caught:
            print(f"      причина: {caught[0][:80]}")

print()
print("  ┌────────────────────────────────────────────────────────────┐")
print("  │ Что видел финопс                │ Что доказал протокол     │")
print("  ├────────────────────────────────────────────────────────────┤")
print("  │ «ваша модель не хуже и на 99%   │ подпись ВАЛИДНА только у │")
print("  │  дешевле» — красивый PDF        │ записи с РЕАЛЬНЫМИ числами│")
print("  ├────────────────────────────────────────────────────────────┤")
print("  │ верить или не верить вендору?  │ проверка БЕЗ вендора за  │")
print("  │                                │ одну команду, $0         │")
print("  └────────────────────────────────────────────────────────────┘")

print(f"\n  ИТОГ: все каналы подлога пойманы, честная запись VALID: "
      f"{all(ok for _, ok in rows)}")
print("  Питч-строка: «Мы не продаём доверие. Мы продаём способ его НЕ НУЖДАТЬСЯ.»")
print("  (аттестационные цифры сверяются с отчётом — 10-я проверка sia-rederive)")

if not all(ok for _, ok in rows):
    print("\n  !!! ДЕМО СЛОМАНО — какой-то канал подлога не пойман !!!", file=sys.stderr)
    raise SystemExit(1)

print("\nDEMO OK")
