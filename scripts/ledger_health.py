#!/usr/bin/env python3
"""Сторож здоровья леджера TrustChain — одна команда оператора.

Ритуал «запись закрыта?»: после каждой новой записи и в проде по крону
(README: anchoring-from-record-1) оператор должен видеть, что цепь
валидна, голова ПОКРЫТА подписанным чекпойнтом и фиксация доложена в
якорное хранилище. До этого скрипта проверка была ручной — и запись №2
прожила 6 дней без чекпойнта, молча.

Проверяет (по убыванию летальности):
  1. Цепь валидна (verify_chain от генезиса, full=True).
  2. Каждый чекпойнт в журнале подписан действующим ключом
     (kid совпадает с декларацией в цепи; верификатор — sia_verifier).
  3. Голова цепи покрыта: max(seq чекпойнтов) == seq головы.
  4. Merkle-корень чекпойнта головы == корню, пересчитанному из цепи.
  5. Файл якоря последнего чекпойнта лежит в ANCHORS_DIR (если задан).

Код выхода: 0 — здоров, 1 — БОЛЬШЕ НЕ ЗДОРОВ (чьё-то доверие сломано),
2 — ошибка чтения. Гейт для крона — просто код выхода.

Локальный запуск:
    python scripts/ledger_health.py
    ANCHORS_DIR=anchors python scripts/ledger_health.py   # + проверка якоря
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "verifier"))

from sia_verifier.core import (  # noqa: E402
    verify_checkpoint,
    verify_chain,
    verify_key_declarations,
)


def _load_jsonl(path: Path) -> list[dict]:
    entries = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if line.strip():
            entries.append(json.loads(line))
    return entries


def main() -> int:
    receipts_dir = Path(os.getenv("RECEIPTS_DIR") or REPO_ROOT / "receipts")
    registry_file = receipts_dir / "registry.jsonl"
    checkpoint_file = receipts_dir / "checkpoints.jsonl"

    if not registry_file.exists():
        print(f"FATAL: {registry_file} not found", file=sys.stderr)
        return 2

    problems: list[str] = []

    # 1. Цепь
    entries = _load_jsonl(registry_file)
    chain = verify_chain(entries)

    if not entries:
        print("chain: EMPTY (nothing to guard yet)")
        return 0

    if not chain.valid:
        print(f"chain: INVALID — {chain.reason} (broken at {chain.broken_at})")
        return 1

    head_seq = max(e.get("seq") or 0 for e in entries)
    print(f"chain: VALID, {chain.entries} entries, head seq={head_seq}")

    if not checkpoint_file.exists():
        print(f"checkpoint: NONE — head seq={head_seq} is UNCOVERED")
        return 1

    checkpoints = _load_jsonl(checkpoint_file)

    # 2. Ключ подписи: последняя key-декларация цепи (entry_type="key",
    # metadata.key_declaration = {kid, public_key, ...}, подписана
    # активным ключом) + проверка самой декларации через
    # verify_key_declarations — сторож не слабее верификатора.
    key = None
    declarations = []

    for e in reversed(entries):
        md = e.get("metadata") or {}

        if md.get("entry_type") == "key" and md.get("key_declaration"):
            declarations.append({
                "declaration": md["key_declaration"],
                "signature": md.get("signature"),
                "signer_kid": md.get("signer_kid"),
            })

    if declarations:
        # verify_key_declarations ожидает декларации в хронологическом порядке
        declarations.reverse()
        keys_valid, kid_table = verify_key_declarations(declarations)

        if not keys_valid:
            print("key declarations: INVALID signature chain")
            return 1

        latest_decl = declarations[-1]["declaration"]
        key = latest_decl["public_key"]
        kid = latest_decl.get("kid")
        cp_kid = checkpoints[-1].get("kid") if checkpoints else None

        if cp_kid is not None and kid != cp_kid:
            problems.append(
                f"latest declared kid {kid} != checkpoint kid {cp_kid} — "
                "checkpoints signed by an undeclared key"
            )
            print(f"key declarations: VALID ({len(declarations)}), kid={kid}")
        else:
            print(f"key declarations: VALID ({len(declarations)}), kid={kid} "
                  f"(matches checkpoint signer)")
    else:
        key = None

    if key is None:
        key = checkpoints[-1].get("public_key")
        print("signing key: taken from latest checkpoint (NO key declaration in chain)")

    for i, cp in enumerate(checkpoints, 1):
        if not verify_checkpoint(cp, key):
            print(f"checkpoint[{i}] seq={cp.get('seq')}: INVALID SIGNATURE")
            return 1
    print(f"checkpoints: {len(checkpoints)} signed snapshot(s), all signatures VALID")

    # 3. Покрытие головы
    cp_max_seq = max(cp.get("seq") or 0 for cp in checkpoints)
    lag = head_seq - cp_max_seq

    if lag > 0:
        print(f"coverage: GAP — head seq={head_seq} > checkpoint seq={cp_max_seq} "
              f"({lag} entry(ies) beyond the latest signed checkpoint)")
        return 1
    print(f"coverage: head seq={head_seq} covered by checkpoint seq={cp_max_seq}")

    # 4. Merkle-корень: корень из чекпойнта головы == пересчёт из цепи.
    import hashlib

    def _leaf(entry_hash: str) -> str:
        return hashlib.sha256(b"\x00" + bytes.fromhex(entry_hash)).hexdigest()

    def _node(left: str, right: str) -> str:
        return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()

    def _mth(hashes: list[str]) -> str:
        if not hashes:
            return hashlib.sha256(b"").hexdigest()
        if len(hashes) == 1:
            return hashes[0]
        k = 1 << (len(hashes).bit_length() - 2) if len(hashes) > 1 else 1
        # крупнейшая степень двойки < n: RFC 6962
        k = 1
        while k * 2 < len(hashes):
            k *= 2
        return _node(_mth(hashes[:k]), _mth(hashes[k:]))

    recomputed_root = _mth([_leaf(e["entry_hash"]) for e in entries if e.get("entry_hash")])
    latest = checkpoints[-1]

    if latest.get("root_hash") != recomputed_root:
        print(f"merkle: MISMATCH — checkpoint root {latest.get('root_hash')[:16]}… "
              f"!= recomputed {recomputed_root[:16]}…")
        return 1
    print(f"merkle: checkpoint root == recomputed tree head (tree_size={latest.get('tree_size')})")

    # 5. Якорный файл последнего чекпойнта
    anchors_dir = Path(os.getenv("ANCHORS_DIR") or "anchors")

    if anchors_dir.exists():
        anchor_name = f"{latest.get('checkpoint_id')}.json"
        anchor_path = anchors_dir / anchor_name

        if anchor_path.exists():
            print(f"anchor: {anchor_name} present in {anchors_dir}")
        else:
            print(f"anchor: MISSING — {anchor_path} (run scripts/anchor_checkpoint.py)")
            return 1
    else:
        print(f"anchor: dir {anchors_dir} not found (set ANCHORS_DIR to enforce)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
