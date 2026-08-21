"""Общая конфигурация окружения: загрузка .env без внешних зависимостей."""
from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(override: bool = False) -> dict[str, str]:
    """Читает KEY=VALUE из .env (cwd и корень проекта), не переопределяя
    реальные переменные окружения (если override=False). Возвращает словарь.
    """
    values: dict[str, str] = {}

    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]

    for env_path in candidates:
        if not env_path.is_file():
            continue

        try:
            for line in env_path.read_text(encoding="utf-8-sig").splitlines():
                line = line.strip()

                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("'\"")

                if key:
                    values.setdefault(key, value)
        except OSError:
            continue

    if override:
        for key, value in values.items():
            os.environ[key] = value

    return values


def resolve_env(name: str) -> str | None:
    """Значение переменной: сначала окружение, затем .env."""
    value = os.environ.get(name)

    if value:
        return value

    return load_dotenv().get(name)
