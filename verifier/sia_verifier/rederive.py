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

Формулы не импортируются из sia.statistics НАМЕРЕННО (принцип независимости
core.py): считаются локально, чтобы ошибка репозиторного кода была видна.
Отличие от core.py: там проверяется подпись/цепь, здесь — методология.
"""
from __future__ import annotations

import argparse
import base64
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

    # --- 2. Канон обязательства и якорь Rekor ---
    anchor_ref = (flow.get("anchor_reference") or "").strip()
    anchor_ok = False
    if check_rekor and anchor_ref.startswith("rekor:"):
        parts = anchor_ref.split(":")
        uuid, index = parts[1], parts[2]
        # канон обязательства строится ЛОКАЛЬНО (см. _commitment_from_flow):
        # занулить reference, канонизировать sort_keys+compact
        commitment = _commitment_from_flow(flow)
        commitment["anchor_reference"] = None
        local_sha512 = hashlib.sha512(_canon(commitment)).hexdigest()

        ok, remote_digest, detail, log_index = _rekor_digest(uuid)
        if ok:
            anchor_ok = remote_digest.lower() == local_sha512
            index_ok = str(log_index) == str(index)
            checks["anchor_rekor"] = {
                "uuid": uuid[:16] + "…",
                "index": index,
                "rekor_log_index": log_index,
                "index_match": index_ok,
                "local_sha512_of_null_reference_commitment": local_sha512,
                "rekor_entry_digest": remote_digest,
                "digest_match": anchor_ok,
            }
            if not anchor_ok:
                failures.append("MISMATCH anchor: sha512(canonical commitment with anchor_reference=null) != Rekor entry digest")
            if not index_ok:
                failures.append(f"MISMATCH anchor index: flow says {index}, Rekor says {log_index}")
        else:
            checks["anchor_rekor"] = {"uuid": uuid[:16] + "…", "error": detail}
            failures.append(f"BLOCKED anchor check: {detail}")
    else:
        checks["anchor_rekor"] = {"skipped_reason": "no rekor: reference in flow"}

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
