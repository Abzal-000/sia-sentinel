"""Атомарные файловые записи для JSON-состояния и append-only леджеров.

Падение процесса посреди записи не должно повреждать состояние:

- JSON-файлы состояния (тенанты, инвойсы, вебхук-подписки) пишутся через
  временный файл в том же каталоге + fsync + ``os.replace`` (атомарный
  rename) — файл всегда либо старый, либо новый, никогда наполовину.
- Append-only леджер пишет одну строку за раз в режиме добавления с
  fsync; при крахе посреди записи читатель отбрасывает повреждённую
  последнюю строку (см. ``receipt_registry._load_entries``).
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def atomic_write_json(path: str | Path, data: Any) -> None:
    """Атомарно записать JSON: mkstemp + fsync + os.replace."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, default=str)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def append_line_durable(path: str | Path, line: str) -> None:
    """Дописать одну строку с fsync (append-only леджеры).

    Одна запись в режиме добавления сохраняет строку целой; fsync
    фиксирует её на диске. Если процесс упадёт посреди записи, читатель
    отбросит повреждённую последнюю строку — цепочка не повреждается.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line if line.endswith("\n") else line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
