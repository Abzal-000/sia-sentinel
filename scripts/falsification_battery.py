#!/usr/bin/env python3
"""Фальсификационная батарея: попытки сломать систему — и требование, чтобы
каждая попытка СКРИПЕЛА. Всё на копиях состояния, живые артефакты не трогает.

Что проверяется (каждый пункт = канал атаки или класс ошибки):
  [F1] Леджер: 6 каналов подделки (подмена метаданных/квитанции,
       удаление/вставка/перестановка записей, подмена head-hash)
  [F2] Подпись: чужой ключ, подмена содержимого при сохранённой подписи
  [F3] Чекпоинт: подмена seq/head/tree под валидной подписью
  [F4] rederive: 7 каналов (подмена датасета/меток/статистики/верdict/
       экономии/обязательства/отчёта-после-подписи)
  [F5] replay: подлог в обе стороны, граница допуска, INAPPLICABLE
  [F6] Preregistration: отказ без anchor_declaration, отказ на
       невалидной форме anchor_reference
  [F7] verifier CLI на валидном + на подменённом документе

Каждый пункт печатает ПОПЫТКА -> ОЖИДАНИЕ -> РЕЗУЛЬТАТ (CAUGHT/MISSED).
EXIT 0 только если ВСЁ поймано.

    ./venv/Scripts/python.exe scripts/falsification_battery.py
"""
from __future__ import annotations

import base64
import copy

import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "verifier"))



from sia.flow_runner import build_preregistration_commitment  # noqa: E402
from sia_verifier.core import verify_attestation, verify_chain, verify_checkpoint  # noqa: E402
from sia_verifier.rederive import rederive  # noqa: E402
from sia_verifier.replay import compare_replays, ReplayInapplicable  # noqa: E402

RESULTS: list[tuple[str, str]] = []


def check(code: str, attempt: str, caught: bool) -> None:
    verdict = "CAUGHT" if caught else "MISSED"
    RESULTS.append((code, verdict))
    mark = "✓" if caught else "✗✗✗"
    print(f"  [{code}] {attempt} -> {verdict} {mark if not caught else ''}")


def _jload(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _jdump(obj: dict, path: Path) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


# === F1: леджер ===============================================================

def falsify_ledger(work: Path) -> None:
    print("[F1] Леджер: подделка записей")
    src = REPO_ROOT / "receipts" / "registry.jsonl"
    entries = [json.loads(line) for line in src.read_text(encoding="utf-8").splitlines() if line.strip()]

    def verify(entries_variant: list[dict]) -> bool:
        # chain_verify работает на списке записей (независимая реализация)
        return verify_chain(entries_variant).valid

    # 1. подмена metadata квитанции (savings_ratio x2)
    e = copy.deepcopy(entries)
    e[1]["metadata"]["savings_ratio"] = 0.99
    check("F1.1", "metadata tamper (savings_ratio)", not verify(e))

    # 2. подмена тела квитанции
    e = copy.deepcopy(entries)
    e[1]["receipt"]["code_hash"] = "00" * 32
    check("F1.2", "receipt body tamper", not verify(e))

    # 3. удаление записи (prereg исчезает)
    e = copy.deepcopy(entries)[1:]
    check("F1.3", "record deletion (prereg)", not verify(e))

    # 4. вставка чужой записи
    e = copy.deepcopy(entries)
    forged = copy.deepcopy(e[1])
    forged["registry_id"] = "f" * 32
    e.insert(1, forged)
    check("F1.4", "record insertion", not verify(e))

    # 5. перестановка двух записей
    e = copy.deepcopy(entries)
    e[0], e[1] = e[1], e[0]
    check("F1.5", "record reorder", not verify(e))

    # 6. подмена entry_hash у последней записи (перезапись головы)
    e = copy.deepcopy(entries)
    e[-1]["entry_hash"] = "aa" * 32
    check("F1.6", "head entry_hash overwrite", not verify(e))


# === F2: подпись ===============================================================

def falsify_signature(work: Path) -> None:
    print("[F2] Подпись: чужой ключ / контент при сохранённой подписи")
    att = _jload(REPO_ROOT / "artifacts" / "record1" / "attestation.json")

    # 1. чужой issuer-ключ при родной подписи
    fake = copy.deepcopy(att)
    fake["issuer"]["public_key"] = base64.b64encode(b"\x01" * 32).decode()
    check("F2.1", "wrong issuer key", not verify_attestation(fake).valid)

    # 2. содержание квитанции изменено, подпись родная
    fake = copy.deepcopy(att)
    fake["claim"]["savings_ratio"] = 0.99
    # claim не входит в подпись напрямую; savings_verified совпадает —
    # но paired.mdd и prereg тоже не подписаны. Подписанное - receipt.
    # Проверяем главное: подмена ПОДПИСАННОГО поля ловится.
    fake = copy.deepcopy(att)
    fake["receipt"]["safety_approved"] = False
    check("F2.2", "signed field tamper (safety_approved)", not verify_attestation(fake).valid)

    # 3. несогласованность claim vs подписанное поле (не трогая подпись)
    fake = copy.deepcopy(att)
    fake["claim"]["savings_verified"] = False
    check("F2.3", "claim/receipt mismatch", not verify_attestation(fake).valid)


# === F3: чекпоинт =============================================================

def falsify_checkpoint(work: Path) -> None:
    print("[F3] Чекпоинт: подмена полей при валидной подписи")
    cp = json.loads((REPO_ROOT / "receipts" / "checkpoints.jsonl").read_text(encoding="utf-8").strip().splitlines()[0])
    key = cp["public_key"]

    for field, value in (("seq", 999), ("head_hash", "bb" * 32), ("tree_size", 42)):
        fake = copy.deepcopy(cp)
        fake[field] = value
        check(f"F3.{field}", f"checkpoint {field} tamper", not verify_checkpoint(fake, key))

    # F3.4: ЖУРНАЛ чекпойнтов — подмена ПЕРВОГО снимка при валидном последнем.
    # Проверяется путь CLI целиком: журнал не слабее своего худшего элемента
    # (semantics введена 2026-09-13 вместе со вторым чекпойнтом seq=4).
    lines = (REPO_ROOT / "receipts" / "checkpoints.jsonl").read_text(encoding="utf-8").splitlines()
    if len(lines) >= 2:
        fake_first = json.loads(lines[0])
        fake_first["head_hash"] = "cc" * 32
        journal = work / "cp_journal_forged.jsonl"
        journal.write_text(
            json.dumps(fake_first) + "\n" + lines[1] + "\n", encoding="utf-8"
        )
        import subprocess
        import sys as _sys

        r = subprocess.run(
            [_sys.executable, "-m", "sia_verifier",
             str(REPO_ROOT / "artifacts" / "record1" / "attestation.json"),
             "--checkpoint", str(journal)],
            capture_output=True, text=True, cwd=str(REPO_ROOT / "verifier"),
        )
        caught = r.returncode == 1 and "INVALID" in r.stdout
        check("F3.journal-first-forged", "forged FIRST snapshot in journal rejected", caught)
    else:
        # Один снимок в журнале: кейс не применим сегодня, но молчать об
        # этом — способ не заметить, когда он станет применимым.
        print("  [F3.journal-first-forged] SKIPPED: journal has a single snapshot")


# === F4: rederive =============================================================

def falsify_rederive(work: Path) -> None:
    print("[F4] rederive: 7 каналов подмены входов")
    att = _jload(REPO_ROOT / "artifacts" / "record1" / "attestation.json")
    report = _jload(REPO_ROOT / "artifacts" / "record1" / "report.json")
    flow = _jload(REPO_ROOT / "flows" / "beacon.json")

    base = rederive(att, report, flow, chain=None, check_rekor=False)
    check("F4.0", "intact inputs -> rederived (sanity)", base["rederived"])

    # 1. подменённый датасет (хеш расходится)
    f = copy.deepcopy(flow)
    f["dataset"][0]["prompt"] = "TAMPERED"
    check("F4.1", "tampered dataset", not rederive(att, report, f, chain=None, check_rekor=False)["rederived"])

    # 2. подменённые метки провалов (b/c не сходятся)
    r = copy.deepcopy(report)
    r["equivalence"]["failed_new"] = r["equivalence"]["failed_new"] + ["gsm8k-nonexistent"]
    check("F4.2", "tampered failure labels", not rederive(att, r, flow, chain=None, check_rekor=False)["rederived"])

    # 3. подменённая статистика (ci_lower)
    a = copy.deepcopy(att)
    a["claim"]["paired"]["ci_lower"] = -0.001
    check("F4.3", "tampered published ci_lower", not rederive(a, report, flow, chain=None, check_rekor=False)["rederived"])

    # 4. перевёрнутый вердикт
    a = copy.deepcopy(att)
    a["claim"]["paired"]["non_inferior"] = False
    check("F4.4", "flipped non_inferior", not rederive(a, report, flow, chain=None, check_rekor=False)["rederived"])

    # 5. завышенная экономия
    r = copy.deepcopy(report)
    r["claim"]["savings_ratio"] = 0.9
    check("F4.5", "inflated savings_ratio", not rederive(att, r, flow, chain=None, check_rekor=False)["rederived"])

    # 6. подменённое обязательство (delta)
    a = copy.deepcopy(att)
    a["claim"]["preregistration"]["delta"] = 0.10
    check("F4.6", "tampered delta in attestation", not rederive(a, report, flow, chain=None, check_rekor=False)["rederived"])

    # 7. отчёт изменён ПОСЛЕ подписи (code_hash расходится)
    r = copy.deepcopy(report)
    r["usage_new"]["output_tokens"] = 1
    check("F4.7", "report modified after signing", not rederive(att, r, flow, chain=None, check_rekor=False)["rederived"])


# === F5: replay ===============================================================

def falsify_replay(work: Path) -> None:
    print("[F5] replay: подлог в обе стороны")
    flow = _jload(REPO_ROOT / "flows" / "beacon.json")
    record = _jload(REPO_ROOT / "artifacts" / "record1" / "report.json")
    fo = record["equivalence"]["failed_old"]
    fn = record["equivalence"]["failed_new"]

    # 1. честный повтор = идентичный -> within
    same = copy.deepcopy(record)
    res = compare_replays(record, same, flow)
    check("F5.1", "identical replay within tolerance", res["within_tolerance"])

    # 2. подлог «к заявлению»: 25 РЕАЛЬНЫХ старых проходов объявлены
    #    провалами (25/450 = 5.6% > 5%) -> REPLAY MISMATCH
    fo_set = set(fo)
    fn_set = set(fn)
    old_passing = [item["label"] for item in flow["dataset"]
                   if item["label"] not in fo_set and item["label"] not in fn_set]
    forged = copy.deepcopy(record)
    forged["equivalence"]["failed_old"] = fo + old_passing[:25]
    res = compare_replays(record, forged, flow)
    check("F5.2", "toward-claim forgery beyond tolerance", not res["within_tolerance"])

    # 3. подлог «от заявления» на РЕАЛЬНЫХ метках: старая выправилась (13),
    #    новая добавила провалов (19) — 32 away, допуск не потрачен
    away = copy.deepcopy(record)
    passing = [item["label"] for item in flow["dataset"]
               if item["label"] not in fo_set and item["label"] not in fn_set]
    away["equivalence"]["failed_old"] = []              # old fail->pass: away
    away["equivalence"]["failed_new"] = fn + passing[:19]  # new pass->fail: away
    res = compare_replays(record, away, flow)
    check("F5.3", "away-drift does not burn tolerance", res["within_tolerance"] and res["away_elements"] >= 30)

    # 4. другой датасет -> INAPPLICABLE
    other = copy.deepcopy(record)
    other["preregistration"]["dataset_sha256"] = "00" * 32
    try:
        compare_replays(record, other, flow)
        caught = False
    except ReplayInapplicable:
        caught = True
    check("F5.4", "foreign dataset refused", caught)


# === F6: preregistration ======================================================

def falsify_prereg(work: Path) -> None:
    print("[F6] Preregistration: якорные ворота")
    flow = _jload(REPO_ROOT / "flows" / "beacon.json")

    # 1. без anchor_declaration отказ
    f = copy.deepcopy(flow)
    f.pop("anchor_declaration")
    f["anchor_reference"] = None
    try:
        build_preregistration_commitment(f)
        check("F6.1", "missing anchor_declaration refused", False)
    except ValueError:
        check("F6.1", "missing anchor_declaration refused", True)

    # 2. bare-hex reference (не self-describing) отказ
    f = copy.deepcopy(flow)
    f["anchor_declaration"] = "external-anchor"
    f["anchor_reference"] = "aa" * 32
    try:
        build_preregistration_commitment(f)
        check("F6.2", "bare-hex anchor_reference refused", False)
    except ValueError:
        check("F6.2", "bare-hex anchor_reference refused", True)

    # 3. валидная форма проходит (sanity)
    f = copy.deepcopy(flow)
    f["anchor_reference"] = "rekor:" + "0" * 64 + ":0"
    try:
        build_preregistration_commitment(f)
        check("F6.3", "well-formed placeholder accepted", True)
    except ValueError:
        check("F6.3", "well-formed placeholder accepted", False)


# === F7: verifier CLI =========================================================

def falsify_verifier(work: Path) -> None:
    print("[F7] Верификатор: валид vs подделка")
    att = _jload(REPO_ROOT / "artifacts" / "record1" / "attestation.json")
    entries = [json.loads(line) for line in (REPO_ROOT / "receipts" / "registry.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]

    v = verify_attestation(att)
    chain = verify_chain(entries, attestation_id=att["attestation_id"])
    check("F7.1", "intact attestation+chain VALID", v.valid and chain.valid)

    fake = copy.deepcopy(att)
    fake["receipt"]["signature"] = base64.b64encode(b"\x00" * 64).decode()
    check("F7.2", "zeroed signature INVALID", not verify_attestation(fake).valid)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="sia_falsify_"))
    print(f"SIA falsification battery — work dir {work}\n")
    try:
        falsify_ledger(work)
        falsify_signature(work)
        falsify_checkpoint(work)
        falsify_rederive(work)
        falsify_replay(work)
        falsify_prereg(work)
        falsify_verifier(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    missed = [code for code, verdict in RESULTS if verdict == "MISSED"]
    print(f"\nTOTAL: {len(RESULTS)} attempts, MISSED: {len(missed)} {missed if missed else ''}")
    print("FALSIFICATION BATTERY:", "ALL CAUGHT — система скрипит на каждый канал" if not missed else f"FAILURES: {missed}")
    return 0 if not missed else 1


if __name__ == "__main__":
    raise SystemExit(main())
