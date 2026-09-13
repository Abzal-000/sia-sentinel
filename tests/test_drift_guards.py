"""Гарды дрейфа «доки-против-кода» для повторяющихся ручных процессов.

Уроки одного дня (2026-09-13), каждый класс ошибки стрелял 2-3 раза:

1. **Число тестов в README** отстало ТРИ раза за день (666/674 → 686 → 705)
   — правило «синхронизировать после финального прогона» держится на
   памяти человека. Гард считает тесты discovery-загрузчиком и сверяет
   с обоими числами в README; следующее добавление теста без обновления
   README красит сьют само.
2. **Версия sia-verifier** синхронна в ТРЁХ местах (pyproject, __init__,
   PyPI-чеклист); при трёх ручных выпусках за день рассинхрон поймали бы
   глаза — теперь ловит тест.
"""
from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _count_tests() -> int:
    """Фактическое число тестов unittest discovery (считает, не запуская)."""

    loader = unittest.TestLoader()
    suite = loader.discover(str(REPO_ROOT / "tests"), top_level_dir=str(REPO_ROOT))
    return suite.countTestCases()


class ReadmeTestCountTestCase(unittest.TestCase):
    """README обязан нести фактическое число тестов — в обоих местах."""

    def test_readme_test_count_matches_reality(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        actual = _count_tests()

        # Оба места, где живёт число: layout-таблица и Status-абзац
        layout = re.search(r"tests/\s+(\d+) tests \(unittest\)", readme)
        status = re.search(r"plus (\d+) tests covering", readme)

        self.assertIsNotNone(
            layout, "README layout line 'tests/          N tests (unittest)' not found"
        )
        self.assertIsNotNone(
            status, "README status phrase 'plus N tests covering' not found"
        )

        self.assertEqual(
            int(layout.group(1)), actual,
            f"README layout says {layout.group(1)}, suite has {actual} — "
            "resync README AFTER the final suite run",
        )
        self.assertEqual(
            int(status.group(1)), actual,
            f"README status says {status.group(1)}, suite has {actual} — "
            "resync README AFTER the final suite run",
        )


class VerifierVersionSyncTestCase(unittest.TestCase):
    """Версия sia-verifier едина в pyproject, __init__ и чеклисте PyPI."""

    def test_verifier_version_is_synchronized(self) -> None:
        with open(REPO_ROOT / "verifier" / "pyproject.toml", "rb") as handle:
            pyproject = tomllib.load(handle)

        from_pyproject = pyproject["project"]["version"]

        init_src = (REPO_ROOT / "verifier" / "sia_verifier" / "__init__.py").read_text(
            encoding="utf-8"
        )
        from_init = re.search(r'__version__ = "([\d.]+)"', init_src)

        checklist = (REPO_ROOT / "docs" / "pypi-release-checklist.md").read_text(
            encoding="utf-8"
        )
        # текущая незагруженная запись в чеклисте: «**X.Y.Z (дата): собрана...»
        from_checklist = re.search(r"\*\*(\d+\.\d+\.\d+) \([\d-]+\): собрана", checklist)

        self.assertIsNotNone(from_init, "__version__ marker missing in __init__.py")
        self.assertIsNotNone(
            from_checklist,
            "pypi-release-checklist.md has no 'current pending release' entry "
            "(pattern: '**X.Y.Z (date): собрана')",
        )

        self.assertEqual(
            from_pyproject, from_init.group(1),
            f"pyproject {from_pyproject} != __init__ {from_init.group(1)}",
        )
        self.assertEqual(
            from_pyproject, from_checklist.group(1),
            f"pyproject {from_pyproject} != checklist {from_checklist.group(1)} — "
            "update docs/pypi-release-checklist.md to the version being shipped",
        )


if __name__ == "__main__":
    unittest.main()
