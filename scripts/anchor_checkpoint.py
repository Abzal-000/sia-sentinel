#!/usr/bin/env python3
"""C4: якорит голову леджера TrustChain во внешнее хранилище.

Создаёт подписанный чекпоинт текущего состояния леджера и публикует его
через настроенные транспорты (файловый каталог ANCHORS_DIR — по умолчанию
``anchors/``; HTTP POST на ANCHOR_URL, если задан).

Запуск из корня проекта::

    python scripts/anchor_checkpoint.py

Крон-пример (анкор каждый час, синхронизация каталога анкоров в S3)::

    0 * * * * cd /srv/sentinel && python scripts/anchor_checkpoint.py \\
        && aws s3 sync anchors/ s3://sentinel-anchors/ --exact-timestamps

Требует те же переменные окружения, что и API: RECEIPTS_DIR (где лежит
ledger) и RECEIPT_SIGNING_KEY (ключ подписи чекпоинтов). Внешний анкор
надо держать в хранилище, недоступном для записи работающему Sentinel, —
иначе компрометация сервера позволит переписать и цепочку, и анкоры.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Запуск из любого места: добавляем корень проекта в sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.anchoring import publish_checkpoint  # noqa: E402
from sentinel.cryptographic_receipts import ReceiptGenerator  # noqa: E402
from sentinel.receipt_registry import ReceiptRegistry  # noqa: E402


def main() -> int:
    registry = ReceiptRegistry()
    generator = ReceiptGenerator()

    checkpoint = registry.create_checkpoint(generator)

    if checkpoint is None:
        print("Ledger is empty — nothing to anchor.")
        return 1

    print(f"seq={checkpoint['seq']} tree_size={checkpoint.get('tree_size')} kid={checkpoint.get('kid')}")

    results = publish_checkpoint(checkpoint)
    anchored = True

    for result in results:
        status = "OK " if result["ok"] else "FAIL"
        print(f"  [{status}] {result['transport']}: {result['detail']}")

        if not result["ok"]:
            anchored = False

    if not anchored:
        print("Some anchor transports failed.")
        return 2

    print("Checkpoint anchored.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
