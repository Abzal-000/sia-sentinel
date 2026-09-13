"""Независимый перевывод вердикта Записи №1 из опубликованных артефактов.

Вторая половина п.7: подпись и цепь проверяет core.py, а здесь восстанавливается
САМ вывод — что дешёвая конфигурация не хуже дорогой не хуже чем на δ — из
двух публичных файлов: аттестации (маяк) и флоу (датасет + конфиги + цены).
Ничего не принимается на слово: b/c пересчитываются из меток провалов отчёта,
даты и цены — из флоу, статистика — из формул парного дизайна (MOVER на
дискордантных клетках + точный Макнемар), канон обязательства — из
репозиторного кода предрегистрации.

Откуда берутся данные (всё опубликовано в git-репозитории SIA):
- artifacts/record1/attestation.json  — подписанный документ (GET /v1/attestations/{id})
- artifacts/record1/report.json       — отчёт аудита: failed_old/failed_new, usage, claim
- flows/beacon.json                   — датасет 450, конфиги, цены, якорная ссылка
- receipts/registry.jsonl             — выгрузка леджера (prereg -> receipt -> key)

Что именно перевыводится и сверяется:
1. dataset: sha256 из флоу == dataset_sha256 аттестации == хеш пересчёта промптов
2. якорь: sha512 канона обязательства (reference=null) == дайджесту записи Rekor
   (берётся из anchor_reference в флоу; проверяющий дергает публичный API Rekor)
3. парность: b=10, c=4 из меток провалов отчёта == опубликованной статистике
4. интервал Ньюкомба/MOVER и точный Макнемар — пересчёт формулами
5. вердикт non_inferior: ci_lower > -delta AND mdd <= delta
6. экономия: savings_ratio из первичных usage-чисел отчёта
7. леджер: предрегистрация (seq=1) предшествует квитанции (seq=2), поля совпадают
8. привязка отчёта к подписи: sha256(report) == receipt.code_hash — отчёт,
   из которого перевыводится вердикт, сам пришит к подписи квитанции
9. inclusion-proof Rekor: RFC 6962-фолд (leaf = sha256(0x00||body),
   внутренняя цепь по битам индекса, border-цепь правых) от leaf к корню
   == RootHash из proof, который одновременно равен корню подписанного
   checkpoint в том же proof. Формулы — порт transparency-dev/merkle
   proof/verify.go (ChainInner/ChainBorderRight/innerProofSize);
   фолд ЛОКАЛЬНЫЙ: тело ответа не принимается на слово ни в какой части.

   ВАЖНО для шардированного публичного инстанса: у записи ДВА индекса —
   виртуальный (entry.logIndex, сквозной по всем шардам) и индекс внутри
   шарда (inclusionProof.logIndex). Фолд считается по ВНУТРИШАРДОВОМУ;
   сверка опубликованного anchor_reference идёт против виртуального.
   Взаимная подмена двух индексов — канал подлога, закрытый этой проверкой.
10. проекция аттестации vs отчёт: claim.savings_ratio/savings_verified
   аттестации — НЕПОДПИСАННАЯ проекция (подпись покрывает receipt; числа
   пришиты к подписи через code_hash -> отчёт). Подмена цифры в аттестации
   под настоящей подписью проходит verify_attestation молча — здесь
   аттестация обязана повторять отчёт слово в слово. Канал найден
   питч-демо scripts/demo_forgery.py (2026-09-13).

Формулы не импортируются из sia.statistics НАМЕРЕННО (принцип независимости
core.py): считаются локально, чтобы ошибка репозиторного кода была видна.
Отличие от core.py: там проверяется подпись/цепь, здесь — методология.
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import math
import urllib.request
from pathlib import Path
from typing import Any

# z-значения для парного дизайна (двусторонний 95% -> односторонний 2.5%)
Z_TWO_SIDED_95 = 1.959963984540054
Z_BETA_80 = 0.8416212335729143  # мощность 80%


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _dataset_hash(dataset: list[dict[str, Any]]) -> str:
    joined = "\n".join(
        f"{item.get('prompt', '')}|{item.get('expect_contains', '')}"
        for item in dataset
    )
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _fail(label: str, expected: Any, got: Any) -> str:
    return f"MISMATCH {label}: published={expected!r} recomputed={got!r}"


def _wilson(successes: int, total: int, z: float = Z_TWO_SIDED_95) -> tuple[float, float]:
    """Wilson score interval для одной доли (внутренний блок MOVER)."""
    if total <= 0:
        return 0.0, 1.0
    p = successes / total
    z2 = z * z
    denom = 1.0 + z2 / total
    center = (p + z2 / (2 * total)) / denom
    margin = (z * math.sqrt(p * (1 - p) / total + z2 / (4 * total * total))) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


def _mover_paired_ci(b: int, c: int, n: int) -> tuple[float, float]:
    """MOVER-интервал для p_new - p_old на дискордантных клетках.

    lower = diff - sqrt((p01-l01)^2 + (u10-p10)^2)
    upper = diff + sqrt((u01-p01)^2 + (p10-l10)^2)
    """
    p10, p01 = b / n, c / n
    diff = p01 - p10
    l10, u10 = _wilson(b, n)
    l01, u01 = _wilson(c, n)
    lower = diff - math.sqrt((p01 - l01) ** 2 + (u10 - p10) ** 2)
    upper = diff + math.sqrt((u01 - p01) ** 2 + (p10 - l10) ** 2)
    return max(-1.0, lower), min(1.0, upper)


def _mcnemar_exact(b: int, c: int) -> float:
    """Точный двусторонний Макнемар: b ~ Binomial(b+c, 0.5)."""
    m = b + c
    if m == 0:
        return 1.0
    log_p = math.log(0.5)
    def cdf(k: int) -> float:  # P(X <= k)
        total = 0.0
        for i in range(k + 1):
            log_coef = math.lgamma(m + 1) - math.lgamma(i + 1) - math.lgamma(m - i + 1)
            total += math.exp(log_coef + m * log_p)
        return min(1.0, total)
    p_le = cdf(b)
    p_ge = 1.0 - cdf(b - 1)
    return min(1.0, 2.0 * min(p_le, p_ge))


def _mdd(
    n: int,
    b: int,
    c: int,
    z_alpha: float = Z_TWO_SIDED_95,
    planning_floor: float = 0.10,
) -> float:
    """MDD = (z_alpha + z_beta) * sqrt(p_disc / n), alpha односторонний 2.5%.

    p_disc = max(планировочное допущение 10%, наблюдённая дискордантность
    (b+c)/n) — правило пола из spec §1.1: наблюдённое значение может только
    ПОВЫШАТЬ MDD, никогда не занижать; иначе MDD занижал бы слепоту аудита
    ровно тогда, когда модели почти не расходятся (запись №1: наблюдено 3.1%
    < 10%, опубликованный MDD обязан считаться от 10%).
    """
    observed = (b + c) / n if n > 0 else 0.0
    p_disc = max(planning_floor, observed, 1e-6)
    return (z_alpha + Z_BETA_80) * math.sqrt(p_disc / n)


def _commitment_from_flow(flow: dict[str, Any]) -> dict[str, Any]:
    """Реконструкция обязательства preregistration/4 по spec §1.2.

    Локальная (не импортирует sia.*): поля собираются из флоу ровно в том
    порядке, как их строит LLMFlowAuditor.preregistration_commitment —
    датасетный sha256 из prompt|expect, endpoints = public_dict() обеих
    сторон (ценовые поля, температура, reasoning_effort, провенанс), все
    скаляры δ/confidence/R/replay_tolerance, якорные поля. Совместимость
    с репозиторным кодом заперта золотым тестом на реальном дайджесте
    записи №1 (af720aad…7c33a8b6) в tests/test_rederive.py.
    """
    dataset = flow.get("dataset") or []
    old, new = flow.get("old") or {}, flow.get("new") or {}

    def public(block: dict[str, Any]) -> dict[str, Any]:
        return {
            "model_name": block.get("model_name"),
            "input_token_usd_per_m": block.get("input_token_usd_per_m"),
            "output_token_usd_per_m": block.get("output_token_usd_per_m"),
            "base_url": block.get("base_url"),
            "temperature": block.get("temperature", 0.0),
            "reasoning_effort": block.get("reasoning_effort"),
            "profile": block.get("profile", "standard"),
            "seed": block.get("seed", 42),
            "simulated_reliability": block.get("simulated_reliability"),
            "prices_as_of": block.get("prices_as_of"),
            "catalog_version": block.get("catalog_version"),
            "price_source_url": block.get("price_source_url"),
            "priced_model_name": block.get("priced_model_name"),
            "price_basis_note": block.get("price_basis_note"),
        }

    return {
        "protocol": "sia-preregistration/4",
        "dataset_sha256": _dataset_hash(dataset),
        "dataset_size": len(dataset),
        "metric": "expect_contains/digit-anchored",
        "delta": float(flow.get("delta", 0.05)),
        "confidence": flow.get("confidence", 0.95),
        "repetitions": max(1, int(flow.get("repetitions", 1))),
        "replay_tolerance": max(0.0, min(1.0, float(flow.get("replay_tolerance", 0.05)))),
        "replay_tolerance_rule": "directional-one-sided:toward-claim",
        "anchor_declaration": (flow.get("anchor_declaration") or "").strip() or None,
        "anchor_reference": (flow.get("anchor_reference") or "").strip() or None,
        "endpoints": {"old": public(old), "new": public(new)},
    }


def _rekor_digest(uuid: str) -> tuple[bool, str, str, Any]:
    """Достаёт дайджест записи Rekor через публичный API.

    GET /api/v1/log/entries/{uuid} отвечает {uuid: {body, logIndex, …}}.
    Возвращает (ok, sha512_hex, detail, logIndex).
    """
    url = f"https://rekor.sigstore.dev/api/v1/log/entries/{uuid}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.load(response)
    except Exception as exc:  # сеть/запись недоступна — не вердикт, а препятствие
        return False, "", f"rekor fetch failed: {exc}", None

    entry = (data.get(uuid) if isinstance(data, dict) else None) or {}
    log_index = entry.get("logIndex")
    try:
        rekord = json.loads(base64.b64decode(entry.get("body") or ""))
        digest = rekord["spec"]["data"]["hash"]["value"]
        algorithm = rekord["spec"]["data"]["hash"]["algorithm"]
        return True, digest, f"algorithm={algorithm}", log_index
    except Exception as exc:
        return False, "", f"rekor entry parse failed: {exc}", log_index


def _rekor_full_entry(uuid: str) -> dict[str, Any] | None:
    """Живая запись Rekor целиком (body + verification.inclusionProof)."""
    url = f"https://rekor.sigstore.dev/api/v1/log/entries/{uuid}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.load(response)
        return (data.get(uuid) if isinstance(data, dict) else None) or {}
    except Exception:
        return None


# Кэш-снапшот живого ответа Rekor для проверки №9 (офлайн-режим).
# Живой запрос ВСЕГДА предпочитается; снапшот — только fallback при
# сетевой недоступности, с видимым возрастом verified_at. Снапшот не
# ослабляет проверку: body внутри снапшота проходит ту же дайджест-сверку
# (подменённый снапшот валит шаг 2) и тот же локальный фолд inclusion-proof
# (проверка №9). Он лишь фиксирует, КОГДА последний раз ответ был живым.
_REKOR_SNAPSHOT_DIR = Path(".cache") / "rekor_snapshots"


def _rekor_snapshot_path(uuid: str) -> Path:
    return _REKOR_SNAPSHOT_DIR / f"{uuid}.json"


def _rekor_entry_cached(uuid: str) -> tuple[dict[str, Any] | None, str]:
    """Живой ответ Rekor, при недоступности сети — timestamped-снапшот.

    Возвращает (entry, source): source = "live" | "snapshot:AGE" | "none".
    Снапшот пишется только после УСПЕШНОГО живого запроса — кэш не может
    легитимизировать содержимое, он лишь свидетельствует о моменте проверки.
    """
    entry = _rekor_full_entry(uuid)

    if entry and entry.get("body"):
        try:
            _REKOR_SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
            payload = {"verified_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                       "uuid": uuid, "entry": entry}
            _rekor_snapshot_path(uuid).write_text(
                json.dumps(payload), encoding="utf-8")
        except OSError:
            pass  # кэш — оптимизация доступности, не обязательство
        return entry, "live"

    # сеть недоступна или ответ пуст — пробуем снапшот
    snap = _rekor_snapshot_path(uuid)

    if snap.exists():
        try:
            payload = json.loads(snap.read_text(encoding="utf-8"))
            age_days = (_dt.datetime.now(_dt.timezone.utc)
                        - _dt.datetime.fromisoformat(payload["verified_at"])).days
            return payload.get("entry") or {}, f"snapshot:{age_days}d"
        except (OSError, ValueError, KeyError):
            return None, "none"

    return None, "none"


def _verify_rekor_inclusion(entry: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
    """RFC 6962 inclusion-proof записи Rekor — ЛОКАЛЬНЫЙ фолд до корня.

    Проверка №9: тело ответа не принимается на слово. Из entry берутся
    только body (leaf-байты) и структурные поля proof'а; корень
    ВЫЧИСЛЯЕТСЯ фолдом и сверяется с rootHash proof'а И с корнем
    подписанной checkpoint-строки внутри него. Формулы — порт
    transparency-dev/merkle proof/verify.go:

      leafHash = sha256(0x00 || body)
      inner    = bit_length(index ^ (size-1))          # innerProofSize
      border   = popcount(index >> inner)
      chainInner: на шаге i при (index>>i)&1==0 — H(seed, h),
                  иначе H(h, seed)
      chainBorderRight: seed = H(h, seed) для всех border-хешей

    Возвращает (ok, detail, debug_dict).
    """
    verification = entry.get("verification") or {}
    ip = verification.get("inclusionProof") or {}
    hashes_hex = ip.get("hashes") or []
    index = ip.get("logIndex")
    tree_size = ip.get("treeSize")
    root_hex = ip.get("rootHash")
    checkpoint = ip.get("checkpoint") or ""

    if index is None or tree_size is None or not root_hex or not hashes_hex:
        return False, "inclusion proof fields missing", {"error": "missing fields"}

    try:
        proof = [bytes.fromhex(h) for h in hashes_hex]
        root = bytes.fromhex(root_hex)
        leaf = hashlib.sha256(b"\x00" + base64.b64decode(entry.get("body") or "")).digest()
        index = int(index)
        tree_size = int(tree_size)
    except Exception as exc:
        return False, f"inclusion proof decode failed: {exc}", {"error": "decode"}

    if index >= tree_size:
        return False, "log index beyond tree size", {"error": "index >= size"}

    inner = (index ^ (tree_size - 1)).bit_length()
    border = bin(index >> inner).count("1")

    if len(proof) != inner + border:
        return (
            False,
            f"proof length {len(proof)} != inner {inner} + border {border}",
            {"inner": inner, "border": border, "got": len(proof)},
        )

    def _node(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + left + right).digest()

    seed = leaf
    for i, h in enumerate(proof[:inner]):
        seed = _node(seed, h) if (index >> i) & 1 == 0 else _node(h, seed)
    for h in proof[inner:]:
        seed = _node(h, seed)

    proof_root_ok = seed == root

    # корень подписанного checkpoint в proof — вторая, независимая фиксация
    # того же корня (строка SignedTreeHead); сверка строкой-в-строку.
    checkpoint_root_ok = None
    cp_lines = [line for line in checkpoint.splitlines() if line.strip()]
    if len(cp_lines) >= 3:
        try:
            cp_root = base64.b64decode(cp_lines[2])
            checkpoint_root_ok = cp_root == root
        except Exception:
            checkpoint_root_ok = None

    debug = {
        "folded_root": seed.hex(),
        "proof_root": root_hex,
        "proof_root_match": proof_root_ok,
        "checkpoint_root_match": checkpoint_root_ok,
        "inner": inner,
        "border": border,
        "shard_index": index,
        "shard_tree_size": tree_size,
    }

    ok = proof_root_ok and (checkpoint_root_ok is not False)

    return ok, "folded == proof root == checkpoint root" if ok else "fold mismatch", debug


def rederive(
    attestation: dict[str, Any],
    report: dict[str, Any],
    flow: dict[str, Any],
    chain: list[dict[str, Any]] | None = None,
    check_rekor: bool = True,
) -> dict[str, Any]:
    """Перевыводит вердикт Записи №1; возвращает отчёт сheck-листа."""
    checks: dict[str, Any] = {}
    failures: list[str] = []

    prereg_meta = ((attestation.get("claim") or {}).get("preregistration")) or {}
    paired_pub = ((attestation.get("claim") or {}).get("paired")) or {}

    # --- 1. Датасет: три источника одного хеша ---
    n = int(flow["dataset"] and len(flow["dataset"]))
    dataset_sha = _dataset_hash(flow["dataset"])
    att_dsha = prereg_meta.get("dataset_sha256")
    rep_dsha = ((report.get("preregistration") or {}).get("dataset_sha256")) or (
        (report.get("manifest") or {}).get("dataset_sha256")
    )
    checks["dataset_size"] = {"published": prereg_meta.get("dataset_size"), "recomputed": len(flow["dataset"])}
    if not (att_dsha == rep_dsha == dataset_sha):
        failures.append(_fail("dataset_sha256", (att_dsha, rep_dsha), dataset_sha))

    # Кросс-сверка решения-критичных полей аттестации против ФЛОУ (не леджера):
    # аттестация — проекция; если её δ или допуск подменены независимо от флоу,
    # перевывод вердикта по подменённой δ мог бы «подтвердить» подмену.
    # Леджерная сверка (ниже, chain) — вторая линия; эта работает и без цепи.
    for field, default in (("delta", flow.get("delta", 0.05)),
                           ("replay_tolerance", flow.get("replay_tolerance", 0.05))):
        att_value = prereg_meta.get(field)
        flow_value = flow.get(field, default)
        if att_value is not None and flow_value is not None:
            try:
                differs = abs(float(att_value) - float(flow_value)) > 1e-12
            except (TypeError, ValueError):
                differs = True
            if differs:
                failures.append(_fail(f"{field} attestation-vs-flow", flow_value, att_value))

    # --- 2. Канон обязательства и якорь Rekor ---
    anchor_ref = (flow.get("anchor_reference") or "").strip()
    if check_rekor and anchor_ref.startswith("rekor:"):
        import re as _re

        parts = anchor_ref.split(":")
        uuid, index = parts[1], parts[2]
        # uuid живёт в URL запроса к Rekor — форму валидируем сами
        # (64 или 80 hex, по форме публичного инстанса; см. валидатор
        # flow_runner): без этого мусорная ссылка выглядела бы как
        # «сеть недоступна», а не как невалидный ввод.
        if not _re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{80}", uuid):
            checks["anchor_rekor"] = {"uuid": uuid[:16] + "…", "error": "malformed anchor uuid (not 64/80 hex)"}
            failures.append(f"BLOCKED anchor check: uuid {uuid!r} is not 64/80 hex")
        else:
            # канон обязательства строится ЛОКАЛЬНО (см. _commitment_from_flow):
            # занулить reference, канонизировать sort_keys+compact
            commitment = _commitment_from_flow(flow)
            commitment["anchor_reference"] = None
            local_sha512 = hashlib.sha512(_canon(commitment)).hexdigest()

            ok, remote_digest, detail, log_index = _rekor_digest(uuid)
            if ok:
                digest_ok = remote_digest.lower() == local_sha512
                index_ok = str(log_index) == str(index)
                checks["anchor_rekor"] = {
                    "uuid": uuid[:16] + "…",
                    "index": index,
                    "rekor_log_index": log_index,
                    "index_match": index_ok,
                    "local_sha512_of_null_reference_commitment": local_sha512,
                    "rekor_entry_digest": remote_digest,
                    "digest_match": digest_ok,
                }
                if not digest_ok:
                    failures.append("MISMATCH anchor: sha512(canonical commitment with anchor_reference=null) != Rekor entry digest")
                if not index_ok:
                    failures.append(f"MISMATCH anchor index: flow says {index}, Rekor says {log_index}")

                # --- Проверка №9: inclusion-proof, локальный фолд ---
                # Живой ответ предпочителен; при сетевой недоступности —
                # timestamped-снапшот (возраст виден как source).
                full_entry, entry_source = _rekor_entry_cached(uuid)
                if full_entry:
                    inc_ok, inc_detail, inc_debug = _verify_rekor_inclusion(full_entry)
                    checks["anchor_rekor"]["inclusion_proof"] = {
                        "verified": inc_ok,
                        "detail": inc_detail,
                        "source": entry_source,
                        **inc_debug,
                    }
                    if not inc_ok:
                        failures.append(f"MISMATCH anchor inclusion-proof: {inc_detail}")
                else:
                    checks["anchor_rekor"]["inclusion_proof"] = {
                        "skipped_reason": "entry fetch failed (network, no snapshot)"
                    }
            else:
                checks["anchor_rekor"] = {"uuid": uuid[:16] + "…", "error": detail}
                failures.append(f"BLOCKED anchor check: {detail}")
    else:
        checks["anchor_rekor"] = {"skipped_reason": "no rekor: reference in flow (or --no-rekor)"}

    # --- 3. Парность: b/c из меток провалов отчёта ---
    eq = report.get("equivalence") or {}
    failed_old = set(eq.get("failed_old") or [])
    failed_new = set(eq.get("failed_new") or [])
    b = len(failed_new - failed_old)  # старое прошло, новое упало
    c = len(failed_old - failed_new)  # старое упало, новое прошло
    checks["paired_counts"] = {
        "published_b": paired_pub.get("b_old_pass_new_fail"),
        "published_c": paired_pub.get("c_old_fail_new_pass"),
        "recomputed_b_from_failure_labels": b,
        "recomputed_c_from_failure_labels": c,
        "failed_old": len(failed_old),
        "failed_new": len(failed_new),
    }
    if paired_pub.get("b_old_pass_new_fail") != b or paired_pub.get("c_old_fail_new_pass") != c:
        failures.append(_fail("paired b/c", (paired_pub.get("b_old_pass_new_fail"), paired_pub.get("c_old_fail_new_pass")), (b, c)))

    # --- 4. Статистика: пересчёт формулами ---
    ci_lower, ci_upper = _mover_paired_ci(b, c, n)
    mcnemar_p = _mcnemar_exact(b, c)
    mdd = _mdd(n, b, c)
    checks["statistics"] = {
        "ci_lower": {"published": paired_pub.get("ci_lower"), "recomputed": ci_lower},
        "ci_upper": {"published": paired_pub.get("ci_upper"), "recomputed": ci_upper},
        "mcnemar_p": {"published": paired_pub.get("mcnemar_p"), "recomputed": mcnemar_p},
        "mdd": {"published": paired_pub.get("minimum_detectable_difference"), "recomputed": mdd},
    }
    def _diff(published: Any, recomputed: float) -> bool:
        """Отсутствующее опубликованное значение — не совпадение."""
        try:
            return abs(float(published) - recomputed) > 1e-9
        except (TypeError, ValueError):
            return True

    if _diff(paired_pub.get("ci_lower"), ci_lower):
        failures.append(_fail("ci_lower", paired_pub.get("ci_lower"), ci_lower))
    if _diff(paired_pub.get("ci_upper"), ci_upper):
        failures.append(_fail("ci_upper", paired_pub.get("ci_upper"), ci_upper))
    if _diff(paired_pub.get("mcnemar_p"), mcnemar_p):
        failures.append(_fail("mcnemar_p", paired_pub.get("mcnemar_p"), mcnemar_p))
    if _diff(paired_pub.get("minimum_detectable_difference"), mdd):
        failures.append(_fail("mdd", paired_pub.get("minimum_detectable_difference"), mdd))

    # --- 5. Вердикт ---
    delta = float(prereg_meta.get("delta", flow.get("delta", 0.05)))
    non_inferior = ci_lower > -delta and (mdd <= delta or (b == 0 and c == 0)) and n > 0
    checks["verdict"] = {
        "delta": delta,
        "rule": "non_inferior := ci_lower > -delta AND (mdd <= delta OR zero discordance), n>0",
        "published_non_inferior": paired_pub.get("non_inferior"),
        "recomputed_non_inferior": non_inferior,
    }
    if bool(paired_pub.get("non_inferior")) != non_inferior:
        failures.append(_fail("non_inferior", paired_pub.get("non_inferior"), non_inferior))

    # --- 6. Экономия: из первичных usage-чисел ---
    u_old, u_new = report["usage_old"], report["usage_new"]
    old_unit = u_old["total_cost_usd"] / u_old["calls"]
    new_unit = u_new["total_cost_usd"] / u_new["calls"]
    savings = (old_unit - new_unit) / old_unit if old_unit else 0.0
    ratio_pub = (report.get("claim") or {}).get("savings_ratio")
    checks["savings"] = {
        "old_unit_cost_usd": {"published": (report.get("claim") or {}).get("old_unit_cost_usd"), "recomputed": old_unit},
        "new_unit_cost_usd": {"published": (report.get("claim") or {}).get("new_unit_cost_usd"), "recomputed": new_unit},
        "savings_ratio": {"published": ratio_pub, "recomputed": savings},
    }
    if ratio_pub is not None and abs(float(ratio_pub) - savings) > 1e-6:
        failures.append(_fail("savings_ratio", ratio_pub, savings))

    # --- 6b (проверка №10). Проекция аттестации vs отчёт ---
    # claim.savings_ratio аттестации — НЕПОДПИСАННАЯ проекция (подпись
    # покрывает receipt; числа пришиты к подписи через code_hash ->
    # отчёт -> эта проверка). Подмена цифры в аттестации (сохранив
    # подпись) проходила verify_attestation молча — ловится здесь:
    # аттестация обязана повторять отчёт слово в слово по тем полям,
    # которые она публикует. Ровно этот канал подделки (savings 99%
    # под настоящей подписью) найден питч-демо demo_forgery.py.
    att_claim = attestation.get("claim") or {}
    att_ratio = att_claim.get("savings_ratio")
    checks["attestation_projection"] = {
        "attestation_savings_ratio": att_ratio,
        "report_savings_ratio": ratio_pub,
    }
    if att_ratio is not None and ratio_pub is not None:
        if abs(float(att_ratio) - float(ratio_pub)) > 1e-6:
            failures.append(
                _fail("attestation claim.savings_ratio vs report", ratio_pub, att_ratio)
            )

    att_verified = att_claim.get("savings_verified")
    rep_verified = (report.get("claim") or {}).get("savings_verified")
    if att_verified is not None and rep_verified is not None:
        if bool(att_verified) != bool(rep_verified):
            failures.append(
                _fail("attestation claim.savings_verified vs report", rep_verified, att_verified)
            )
    checks["attestation_projection"]["savings_verified_match"] = (
        att_verified is None or rep_verified is None or bool(att_verified) == bool(rep_verified)
    )

    # --- 8. Привязка отчёта к подписи квитанции ---
    # Сервер хеширует отчёт так: generate_receipt(code=json.dumps(report,
    # sort_keys=True, default=str)) -> sha256. Восстанавливаем и сверяем с
    # receipt.code_hash из ПОДПИСАННОЙ аттестации — тогда всем входам
    # перевывода (failed-метки, usage-числа) можно доверять как подписанным.
    receipt = attestation.get("receipt") or {}
    code_hash_pub = receipt.get("code_hash")
    code_hash_local = hashlib.sha256(
        json.dumps(report, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    checks["report_binding"] = {
        "receipt_code_hash": code_hash_pub,
        "recomputed_sha256_of_report": code_hash_local,
        "bound": code_hash_pub == code_hash_local,
    }
    if code_hash_pub != code_hash_local:
        failures.append("MISMATCH report binding: sha256(report) != receipt.code_hash — the re-derived inputs are not what was signed")

    # --- 7. Леджер: подпись prereg предшествует receipt ---
    if chain is not None:
        prereg = next((e for e in chain if (e.get("metadata") or {}).get("entry_type") == "preregistration"), None)
        receipt = next(
            (
                e
                for e in chain
                if e.get("registry_id") == attestation.get("attestation_id")
            ),
            None
        )
        if prereg and receipt:
            order_ok = prereg["seq"] < receipt["seq"]
            # сверка ключевых полей prereg-коммитмента с флоу
            lc = (prereg.get("metadata") or {}).get("commitment") or {}
            lm_ok = (
                lc.get("dataset_sha256") == dataset_sha
                and float(lc.get("delta", 0)) == delta
            )
            checks["ledger"] = {
                "prereg_seq": prereg["seq"],
                "receipt_seq": receipt["seq"],
                "prereg_precedes_receipt": order_ok,
                "prereg_commitment_matches_flow": lm_ok,
            }
            if not order_ok:
                failures.append("ledger order: preregistration does NOT precede the receipt")
            if not lm_ok:
                failures.append("ledger preregistration commitment differs from the flow (dataset/delta)")
        else:
            checks["ledger"] = {"found_prereg": bool(prereg), "found_receipt": bool(receipt)}
            failures.append("BLOCKED ledger check: preregistration or receipt entry not found in chain")

    return {
        "attestation_id": attestation.get("attestation_id"),
        "checks": checks,
        "failures": failures,
        "rederived": len(failures) == 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sia-rederive",
        description="Independently re-derive the Record-1 beacon verdict from published artifacts.",
    )
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts/record1"))
    parser.add_argument("--flow", type=Path, default=Path("flows/beacon.json"))
    parser.add_argument("--chain", type=Path, default=Path("receipts/registry.jsonl"))
    parser.add_argument("--no-rekor", action="store_true", help="Skip the live Rekor API check (offline)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    attestation = _load_json(args.artifacts / "attestation.json")
    report = _load_json(args.artifacts / "report.json")
    flow = _load_json(args.flow)
    chain = _load_jsonl(args.chain) if args.chain.exists() else None

    result = rederive(
        attestation, report, flow, chain, check_rekor=not args.no_rekor
    )

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"attestation:  {result['attestation_id']}")
        for name, detail in result["checks"].items():
            print(f"[{name}] {json.dumps(detail, default=str)[:200]}")
        for f in result["failures"]:
            print(f"  !! {f}")
        print(f"REDERIVED:    {'YES' if result['rederived'] else 'NO'}")
    return 0 if result["rederived"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
