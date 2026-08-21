#!/usr/bin/env python3
"""Демо TrustChain-леджера: хеш-цепочка, tamper-evidence, чекпоинты.

Показывает офлайн (без API-ключей и сервера), как реестр квитанций
Proof-of-Savings превращается в tamper-evident журнал:
  1. Квитанции регистрируются в хеш-цепочку (entry_hash -> prev_hash).
  2. Подмена/удаление/перестановка записей обнаруживаются проверкой цепочки.
  3. Голова цепочки якорится подписанным чекпоинтом (Ed25519).
  4. Чекпоинт проверяется только публичным ключом — без секрета подписи.

Запуск:  python demo_trustchain_ledger.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sentinel.cryptographic_receipts import ReceiptGenerator, ReceiptVerifier
from sentinel.receipt_registry import ReceiptRegistry


def banner(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        storage_dir = str(Path(tmp) / "receipts")

        generator = ReceiptGenerator("demo-trustchain-key")
        verifier = ReceiptVerifier(generator.get_public_key())
        registry = ReceiptRegistry(storage_dir)

        banner("1. Регистрация квитанций в хеш-цепочку")
        for name in ("audit-alpha", "audit-beta", "audit-gamma"):
            receipt = generator.generate_receipt(
                evidence_id=f"pos-{name}",
                code=json.dumps({"flow": name}),
                safety_approved=True,
                trust_level="JUNIOR",
                manifest={"flow_name": name},
            )
            registry_id = registry.register(receipt, metadata={"flow_name": name})
            print(f"  зарегистрирована {name} -> {registry_id[:12]}...")

        head = registry.head()
        print(f"\n  голова цепочки: seq={head['seq']} hash={head['entry_hash'][:16]}...")

        banner("2. Проверка цепочки (должна быть валидна)")
        result = registry.verify_chain()
        print(f"  valid={result['valid']} entries={result['entries']}")
        assert result["valid"], "цепочка должна быть валидна после регистрации"

        banner("3. Подмена записи -> обнаруживается")
        registry_file = Path(storage_dir) / "registry.jsonl"
        entries = [
            json.loads(line)
            for line in registry_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        entries[1]["receipt"]["safety_approved"] = False  # подделка
        registry_file.write_text(
            "\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8"
        )

        tampered = registry.verify_chain()
        print(f"  valid={tampered['valid']} broken_at={tampered['broken_at']}")
        print(f"  причина: {tampered['reason']}")
        assert not tampered["valid"], "подмена должна быть обнаружена"

        # Восстанавливаем оригинал
        entries[1]["receipt"]["safety_approved"] = True
        registry_file.write_text(
            "\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8"
        )
        assert registry.verify_chain()["valid"], "цепочка восстановлена"

        banner("4. Якорение головы подписанным чекпоинтом")
        checkpoint = registry.create_checkpoint(generator)
        print(f"  checkpoint_id={checkpoint['checkpoint_id'][:12]}...")
        print(f"  seq={checkpoint['seq']} head_hash={checkpoint['head_hash'][:16]}...")
        print(f"  signature={checkpoint['signature'][:24]}...")

        banner("5. Проверка чекпоинта только публичным ключом")
        ok = registry.verify_checkpoint(checkpoint, verifier)
        print(f"  подпись валидна: {ok}")
        assert ok, "чекпоинт должен проверяться публичным ключом"

        # Подделка чекпоинта
        forged = dict(checkpoint)
        forged["head_hash"] = "f" * 64
        forged_ok = registry.verify_checkpoint(forged, verifier)
        print(f"  подделанный чекпоинт валиден: {forged_ok}")
        assert not forged_ok, "подделка чекпоинта должна быть обнаружена"

        banner("Итог")
        print("  TrustChain-леджер: подмена, удаление и перестановка записей")
        print("  обнаруживаются; голова якорится подписанным чекпоинтом,")
        print("  проверяемым любой стороной по публичному ключу.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
