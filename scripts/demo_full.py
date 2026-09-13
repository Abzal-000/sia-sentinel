"""ПОЛНОЕ ДЕМО SIA Sentinel: живой сервер, полный продуктовый цикл.

Сцена: финопс-команда платит за премиум-модель; поставщик предлагает
дешёвую. SIA доказывает, кто прав. Всё изолировано (tmp-состояние),
simulated-режим (демо без API-ключей), но весь криптоконтур настоящий.
"""
import os  # noqa: E402
import sys  # noqa: E402
import json
import tempfile
import time
from pathlib import Path  # noqa: E402

tmp = tempfile.mkdtemp(prefix="sia_demo_")
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
    # Глобальный стор ключей — ТОЖЕ в tmp: без этого менеджер читает
    # репозиторийный api_keys.json (накопил 206 ключей от тестовых прогонов),
    # находит там активных platform-админов и ПРОПУСКАЕТ бутстрап —
    # демо-ключ не зарегистрирован, шаг 7 (checkpoint) падает 401.
    "API_KEYS_FILE": str(Path(tmp) / "api_keys.json"),
})
# Запуск из любого cwd: корень репо в sys.path ДО импорта sentinel
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import importlib  # noqa: E402
import sentinel.api as api  # noqa: E402
importlib.reload(api)
from fastapi.testclient import TestClient  # noqa: E402
c = TestClient(api.app)


def step(n, title):
    print(f"\n{'='*70}\nШАГ {n}. {title}\n{'='*70}")


# ---- ШАГ 1
step(1, "Клиент приходит в систему (self-service signup)")
r = c.post("/v1/signup", json={"name": "ФинОпс Департамент ТОО", "tenant_id": "finops"})
assert r.status_code == 201, r.text
key = r.json()["api_key"]
H = {"X-API-Key": key}
print("  tenant: finops (план free) -> API-ключ выдан, показан ОДИН раз")
print(f"  ключ: {key[:12]}...{key[-4:]}  (хранится хешированным)")

# ---- ШАГ 2
step(2, "Предрегистрация: ворота аудита фиксируются В ЦЕПИ ДО прогона")
hard_items = [
    {"label": f"hard{i}", "prompt": f"Сложный кейс #{i}: интеграл по контуру",
     "expect_contains": f"ANSWER={i}x7"}
    for i in range(6)
]
easy_items = [
    {"label": f"q{i}", "prompt": f"Служебный вопрос #{i}: 2+2? ANSWER=4",
     "expect_contains": "ANSWER=4"}
    for i in range(24)
]
FLOW = {
    "kind": "llm_flow", "name": "support-bot-gpt4-to-mini",
    "delta": 0.15, "confidence": 0.95, "repetitions": 1,
    "dataset": easy_items + hard_items,
    "old": {"model_name": "gpt4-premium", "profile": "verbose",
            "input_token_usd_per_m": 10.0, "output_token_usd_per_m": 30.0},
    # Заявленная надёжность симулятора (E6, публичное допущение в манифесте):
    # дешёвая модель идеальна на лёгких и сыпется на ~10% сложных.
    "new": {"model_name": "mini-8b", "profile": "standard",
            "input_token_usd_per_m": 0.15, "output_token_usd_per_m": 0.60,
            "simulated_reliability": 0.9},
    "anchor_declaration": "unanchored",
}
r = c.post("/v1/preregistrations", json={"flow": FLOW}, headers=H)
assert r.status_code == 200, r.text
prereg_id = r.json()["preregistration_id"]
com = r.json()["commitment"]
print(f"  preregistration_id: {prereg_id[:16]}...")
print(f"  зафиксировано ДО результата: delta={com['delta']}, n={com['dataset_size']}, метрика={com['metric']}")
print(f"  dataset_sha256: {com['dataset_sha256'][:24]}...")

# ---- ШАГ 3
step(3, "Аудит: replay нагрузки через ОБЕ конфигурации (async job)")
r = c.post("/v1/audits", json={"flow": FLOW}, headers=H)
assert r.status_code == 202, r.text
job = r.json()["audit_id"]
print(f"  job_id: {job[:16]}...  статус: pending")
for _ in range(200):
    s = c.get(f"/v1/audits/{job}", headers=H).json()
    if s["status"] in ("completed", "failed"):
        break
    time.sleep(0.05)
assert s["status"] == "completed", s.get("error")
res = s["result"]
reg_id = res["registry_id"]
report = res["report"]
paired = report["equivalence"]["paired"]
claim = report["claim"]
print("  статус: completed OK")
print(f"  режим: {report['mode']} (в демо; в бою — live с реальными токенами)")
print(f"  Парная статистика: n={paired['n_pairs']}, b={paired['b_old_pass_new_fail']}, c={paired['c_old_fail_new_pass']}")
print(f"  CI p_new-p_old: [{paired['ci_lower']:.4f}, {paired['ci_upper']:.4f}] при delta={paired['delta']}")
print(f"  MDD={paired['minimum_detectable_difference']:.4f} (<= delta -> ворота открыты)")
print(f"  ВЕРДИКТ: non_inferior={paired['non_inferior']}")
print(f"  Экономия: {claim['savings_ratio']*100:.1f}%  (${claim['old_unit_cost_usd']*1000:.2f} -> ${claim['new_unit_cost_usd']*1000:.2f} за 1k вызовов)")

# ---- ШАГ 4
step(4, "Квитанция: Ed25519-подпись + регистрация в TrustChain")
receipt = res["receipt"]
r = c.get(f"/v1/receipts/{reg_id}/verify", headers=H)
print(f"  registry_id: {reg_id}")
print(f"  подпись валидна: {r.json()['valid']}  kid: {r.json()['kid']}")
print(f"  code_hash: {receipt['code_hash'][:24]}... (хеш отчёта под подписью)")

# ---- ШАГ 5
step(5, "Проверка честности: вердикт вынесен против ЗАРАНЕЕ объявленных ворот")
r = c.get(f"/v1/preregistrations/{prereg_id}/verify/{reg_id}")
print(f"  prereg предшествует квитанции, параметры совпали: {r.json()}")

# ---- ШАГ 6
step(6, "TrustChain: хеш-цепочка и Merkle-дерево (RFC 6962)")
head = c.get("/v1/ledger/head").json()
print(f"  голова: seq={head['seq']}, tree_size={head['tree_size']}")
print(f"  root_hash: {head['root_hash'][:24]}...")
v = c.get("/v1/ledger/verify", params={"full": "true"}).json()
print(f"  цепь: valid={v['valid']}, записей={v['entries']}")
inc = c.get(f"/v1/ledger/inclusion/{reg_id}").json()
print(f"  inclusion proof: leaf {inc['leaf_index']}, путь из {len(inc['proof'])} шагов")
sys.path.insert(0, "verifier")
from sia_verifier import verify_inclusion  # noqa: E402
head2 = c.get("/v1/ledger/head").json()
ok = verify_inclusion(inc["entry_hash"], inc["leaf_index"], inc["tree_size"], head2["root_hash"], inc["proof"])
print(f"  независимое сворачивание в корень: {ok}")

# ---- ШАГ 7
step(7, "Чекпоинт: подписанный коммитмент на состояние леджера")
r = c.post("/v1/ledger/checkpoint", headers={"X-API-Key": os.environ["PLATFORM_ADMIN_API_KEY"]})
assert r.status_code == 200, r.text
cp = r.json()["checkpoint"]
print(f"  checkpoint_id: {cp['checkpoint_id'][:16]}...")
print(f"  покрывает seq={cp['seq']}, head={cp['head_hash'][:20]}..., tree={cp['tree_size']}/{cp['root_hash'][:20]}...")
print("  -> в бою публикуется вовне (Rekor/WORM), и история не переписывается")

# ---- ШАГ 8
step(8, "Аттестация: документ, который проверяет ТРЕТЬЯ СТОРОНА")
r = c.post("/v1/tenants/finops/settings", json={"publish_attestations": True}, headers=H)
assert r.status_code == 200
r = c.get(f"/v1/attestations/{reg_id}")
att = r.json()
print(f"  spec: {att['spec']}  subject: {att['subject']['flow_name']}")
print(f"  claim: savings_verified={att['claim']['savings_verified']}, ratio={att['claim']['savings_ratio']}")
print(f"  paired-блок: n={att['claim']['paired']['n_pairs']}, verdict={att['claim']['paired']['non_inferior']}")
print(f"  prereg-блок: delta={att['claim']['preregistration']['delta']}")
from sia_verifier import verify_attestation  # noqa: E402
verdict = verify_attestation(att)
print()
print(f"  >>> НЕЗАВИСИМЫЙ ВЕРИФИКАТОР (sia-verifier): valid={verdict.valid}, подпись={verdict.receipt_signature_valid}, claim={verdict.claim_consistent}")
print("  >>> pip install sia-verifier — работает у ЛЮБОГО человека без доверия к нам")

# ---- ШАГ 9
step(9, "Публичная витрина и бейдж")
r = c.get("/v1/attestations")
cards = r.json()["attestations"]
print(f"  /v1/attestations: {len(cards)} записей (opt-in)")
print(f"  /registry?lang=kk|ru|en — витрина; /attestations/{reg_id[:12]}... — портал верификации")
r = c.get(f"/v1/attestations/{reg_id}/badge.svg")
print(f"  badge.svg: {len(r.content)} bytes, embed: <img src=.../badge.svg>")

# ---- ШАГ 10
step(10, "Savings Autopilot: найди дешёвую конфигурацию, которая НЕ роняет качество")
# Скрининг на СМЕШАННОМ датасете: 8 лёгких + 4 сложных элемента, где слабая
# модель реально сыпется (её seeded-ответы не содержат ожидаемой строки).
# Урок демо: simulated_reliability НЕ поле каталога ModelSpec — различие
# качества кандидатов в simulated-режиме создаётся ПРОФИЛЕМ и содержанием
# элементов (сложные вопросы делают seeded-промахи для всех, но дискордантно).
mixed = easy_items[:8] + hard_items[:4]
OPT = {
    "kind": "optimize", "name": "autopilot-screen",
    "dataset": mixed,
    "baseline": {"model_name": "gpt4-premium", "profile": "verbose",
                 "input_token_usd_per_m": 10.0, "output_token_usd_per_m": 30.0},
    "candidates": [
        {"model_name": "mini-8b", "profile": "standard",
         "input_token_usd_per_m": 0.15, "output_token_usd_per_m": 0.60},
        {"model_name": "nano-3b", "profile": "concise",
         "input_token_usd_per_m": 0.05, "output_token_usd_per_m": 0.20,
         "simulated_reliability": 0.5},
        {"model_name": "mid-70b", "profile": "standard",
         "input_token_usd_per_m": 0.60, "output_token_usd_per_m": 2.40},
    ],
    "quality_floor": 0.9, "confidence": 0.95,
}
r = c.post("/v1/optimize", json={"flow": OPT}, headers=H)
assert r.status_code == 202, r.text
job2 = r.json()["audit_id"]
for _ in range(400):
    s2 = c.get(f"/v1/optimize/{job2}", headers=H).json()
    if s2["status"] in ("completed", "failed"):
        break
    time.sleep(0.05)
assert s2["status"] == "completed", s2.get("error")
rec = s2["result"]["report"]["recommendation"]
print("  кандидатов на входе: 3; скрининг -> финальный аудит -> рекомендация:")
print(f"  >>> {json.dumps(rec, ensure_ascii=False)[:220]}")
if rec:
    ratio = rec.get("savings_ratio") or 0
    print(f"  экономия рекомендации: {ratio*100:.1f}% при сохранении качества >= {OPT['quality_floor']}")

# ---- САМОПРОВЕРКА ДЕМО (гарантии для CI: каждый этап должен был пройти)
# Демо — самый производительный охотник за багами проекта (нашло
# schema-дыру ModelSpec и дыру неподписанной проекции); в CI оно обязано
# не только печатать, но и ГРОМКО падать, если любая из гарантий сломана.
assert v.get("valid") and v["entries"] == 2, "шаг 6: цепь не 2 записи (prereg + квитанция)"
assert cp.get("seq") == head["seq"], "шаг 7: чекпойнт не покрывает голову"
assert verdict.valid, "шаг 8: независимый верификатор не подтвердил аттестацию"
assert cards, "шаг 9: публичная витрина пуста"
assert rec, "шаг 10: автопилот не дал рекомендации"
assert rec.get("model_name") != "nano-3b", "шаг 10: автопилот рекомендовал заведомо плохой кандидат"

# ---- ФИНАЛ
print()
print("=" * 70)
print("ДЕМО ЗАВЕРШЕНО: signup -> prereg -> аудит -> квитанция -> леджер ->")
print("чекпоинт -> аттестация -> независимая верификация -> витрина -> автопилот")
print("=" * 70)
print(f"Состояние демо: {tmp} (изолировано; боевой контур — та же цепочка с live-эндпоинтами)")
print("DEMO OK")
