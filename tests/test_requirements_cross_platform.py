"""Гард: requirements.txt обязан оставаться кросс-платформенным.

Пойманная в бою дыра CI (2026-09-19)
----------------------------------
`requirements.txt` содержал `pywin32==312` — Windows-only пакет без wheel для
Linux. CI (`ubuntu-latest`) ставит ИМЕННО этот файл, поэтому джоб падал на шаге
"Install dependencies" за ~2 секунды: до старта тестов, до ruff, до mypy.

Почему это было неочевидно: локально на Windows установка проходит, все 783
теста зелёные, `requirements-docker.txt` уже был вычищен (там есть комментарий
"minus Windows-only packages (pywin32)"). Красный статус при полностью зелёной
локальной проверке выглядит как «CI сломан/списал минуты», и коммит
9774738 так и диагностировал реальную проблему уровня аккаунта. Настоящая
причина была три коммита глубже.

Этот тест закрывает класс ошибок: Windows-only пакет в общем requirements
ломает Linux-CI мгновенно и без внятной диагностики.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Пакеты, у которых нет Linux-wheel: на ubuntu их установка провалится.
WINDOWS_ONLY = re.compile(
    r"^(pywin32|pywin32-ctypes|pywinpty|pywin|wincert|win32set|"
    r"pywin32-postinstall|pywin32-ctypes)",
    re.IGNORECASE,
)


def _requirement_lines(path: Path) -> list[tuple[int, str]]:
    """Номера строк и содержимое значимых строк requirements-файла."""
    if not path.exists():
        return []
    out: list[tuple[int, str]] = []
    for number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            out.append((number, line))
    return out


class RequirementsCrossPlatformTestCase(unittest.TestCase):
    def test_main_requirements_has_no_windows_only_packages(self) -> None:
        offenders = [
            f"requirements.txt:{n}: {line}"
            for n, line in _requirement_lines(ROOT / "requirements.txt")
            if WINDOWS_ONLY.match(line)
        ]
        self.assertEqual(
            offenders,
            [],
            "Windows-only пакеты в requirements.txt ломают Linux-CI. "
            "Перенесите их в requirements-win.txt. Найдено: "
            + ", ".join(offenders),
        )

    def test_docker_requirements_has_no_windows_only_packages(self) -> None:
        offenders = [
            f"requirements-docker.txt:{n}: {line}"
            for n, line in _requirement_lines(ROOT / "requirements-docker.txt")
            if WINDOWS_ONLY.match(line)
        ]
        self.assertEqual(offenders, [])

    def test_windows_requirements_exists_if_pywin32_present_anywhere(self) -> None:
        """Если pywin32 нужен, он обязан жить в отдельном файле — и он должен
        существовать, чтобы локальная Windows-разработка не сломалась."""
        win_file = ROOT / "requirements-win.txt"
        self.assertTrue(
            win_file.exists(),
            "requirements-win.txt отсутствует, хотя Windows-only пакет "
            "вынесен из общего requirements",
        )
        win_names = {line.split("==")[0].lower() for _, line in _requirement_lines(win_file)}
        self.assertIn("pywin32", win_names)

    def test_no_pinned_windows_package_escapes_to_ubuntu(self) -> None:
        """Общий список и docker-список не должны расходиться по составу
        Windows-only части: если в общий вернётся pywin32 — тест упадёт."""
        common = {line.split("==")[0].lower() for _, line in _requirement_lines(ROOT / "requirements.txt")}
        docker = {line.split("==")[0].lower() for _, line in _requirement_lines(ROOT / "requirements-docker.txt")}

        # pywin32 не должен быть ни в одном из Linux-файлов
        self.assertNotIn("pywin32", common)
        self.assertNotIn("pywin32", docker)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
