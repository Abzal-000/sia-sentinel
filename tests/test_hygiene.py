"""Структурный гард: пакетная поверхность = файлы на диске.

Урок (скан 2026-09-06): в sentinel/__pycache__ жили байткод-призраки
удалённых модулей (agent_identity, cache, credential_manager,
evidence_store_db, trust_credentials, verification_network) — шесть
модулей, которых нет в дереве, но которые «существуют» в рантайме
сборки/инструментов и путают инвентаризацию. Python 3 не импортирует
из __pycache__ без сорца, так что это только мусор, — но мусор
воспроизводится: любой, кто удалит .py и оставит кеш, воссоздаст тот же
туман. Тест обязывает кеш совпадать с деревом.
"""
from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Пакеты, чей __pycache__ проверяем
PACKAGES = ("sentinel", "sia", "sdk/sia_sentinel")


class StaleBytecodeTestCase(unittest.TestCase):
    def test_no_pyc_without_source(self) -> None:
        stale: list[str] = []

        for package in PACKAGES:
            pycache = REPO_ROOT / package / "__pycache__"

            if not pycache.is_dir():
                continue

            for pyc in pycache.glob("*.pyc"):
                module_name = pyc.name.split(".")[0]

                if module_name == "__init__":
                    source = pycache.parent / "__init__.py"
                else:
                    source = pycache.parent / f"{module_name}.py"

                if not source.exists():
                    stale.append(str(pyc.relative_to(REPO_ROOT)))

        self.assertEqual(stale, [], "stale .pyc without .py source — delete the cache")
