"""Гард «клон обязан верифицировать» (P1, 2026-09-14).

Урок дня-2, доказанный красным: `receipts/` был в .gitignore — вторая
точка существования защищала код, но НЕ леджер. Свежий клон репозитория
не мог верифицировать ни одну запись: файлы цепи физически отсутствовали.
Локально всё было зелёным — дыра жила ровно в разнице между «рабочим
каталогом» и «что видит git».

Этот гард закрывает класс, а не случай: тест сверяет набор файлов в
HEAD с полным списком, который нужен ВНЕШНЕМУ проверяющему для
самостоятельной верификации обеих публичных записей. Любой файл,
попавший в .gitignore или не добавленный в git, красит сьют — какой бы
зелёной ни была локальная жизнь.

Красное доказательство требовалось проектом: баг пойман вживую
2026-09-14 (свежий клон не находил receipts/registry.jsonl).
"""
from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Полный аутсайдер-набор: аттестации обеих записей, леджер (цепь +
# чекпойнты), внешний якорь, флоу с датасетами и конфигами обеих сторон.
OUTSIDER_FILES = (
    "artifacts/record1/attestation.json",
    "artifacts/record1/report.json",
    "artifacts/demo-live/attestation.json",
    "artifacts/demo-live/receipt.json",
    "artifacts/demo-live/report.json",
    "receipts/registry.jsonl",
    "receipts/checkpoints.jsonl",
    "anchors/00f5f3a4a442423f8858ddf3999fa52c.json",
    "flows/beacon.json",
    "flows/live_demo.json",
)


def _tracked_files() -> set[str]:
    """Файлы в HEAD: то, что получит посторонний, клонировав репозиторий."""
    proc = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {proc.stderr}")
    return set(proc.stdout.split())


def _committed_state_ok() -> bool:
    """Рабочее дерево чисто для trust-путей: незакоммиченные изменения
    в аутсайдер-наборе = клон расходится с локальной «зеленью»."""
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--", *OUTSIDER_FILES],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode == 0 and not proc.stdout.strip()


class CloneMustVerifyGuard(unittest.TestCase):
    """Всё, что нужно постороннему, обязано быть в git — и закоммичено."""

    def test_outsider_files_are_tracked_in_head(self) -> None:
        tracked = _tracked_files()
        missing = [f for f in OUTSIDER_FILES if f not in tracked]
        self.assertEqual(
            missing,
            [],
            "External verifiers clone the repo and expect these files; "
            "they are missing from git (added to .gitignore or never "
            "committed): " + ", ".join(missing),
        )

    def test_outsider_files_have_no_uncommitted_changes(self) -> None:
        # HEAD-набор (тест выше) плюс чистота дерева — вместе дают
        # «клон == локаль» для trust-путей на момент прогона сьюта
        self.assertTrue(
            _committed_state_ok(),
            "Trust-bearing files have uncommitted changes — the clone "
            "diverges from the local state that the suite just verified. "
            "Commit before trusting green.",
        )

    def test_outsider_files_exist_on_disk(self) -> None:
        # HEAD-тест ловит git-сторону; этот — физическую: файл может
        # быть в HEAD, но удалён из рабочего каталога (checkout-расхождение)
        missing = [f for f in OUTSIDER_FILES if not (REPO_ROOT / f).exists()]
        self.assertEqual(missing, [], "Missing on disk: " + ", ".join(missing))


class CloneActuallyVerifies(unittest.TestCase):
    """Симуляция аутсайдера: ядро верификации на файлах ИЗ КЛОНА.

    Не полный subprocess-клон (дорого для каждого прогона) — но
    идентичная проверка данными, которые git отдаёт постороннему:
    аттестация/цепь/чекпойнты читаются через `git show HEAD:...`,
    а не с рабочего диска. Если файл есть, но его HEAD-версия
    разошлась с рабочей — это поймает и это.
    """

    def _head_content(self, rel: str) -> str:
        proc = subprocess.run(
            ["git", "show", f"HEAD:{rel}"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0:
            self.fail(f"HEAD:{rel} not readable: {proc.stderr}")
        return proc.stdout

    def test_head_attestations_verify_against_head_chain(self) -> None:
        import sys

        verifier_root = REPO_ROOT / "verifier"
        sys.path.insert(0, str(verifier_root))
        try:
            from sia_verifier.core import verify_chain
        finally:
            sys.path.remove(str(verifier_root))

        attestation = json.loads(self._head_content("artifacts/record1/attestation.json"))
        chain = [
            json.loads(line)
            for line in self._head_content("receipts/registry.jsonl").splitlines()
            if line.strip()
        ]

        attestation_id = attestation["attestation_id"]
        verdict = verify_chain(chain, attestation_id)
        self.assertTrue(
            verdict.valid,
            f"HEAD chain does not verify: {verdict.reason} at {verdict.broken_at}",
        )
        self.assertTrue(
            verdict.contains_attestation,
            "record-1 attestation not found in HEAD chain",
        )


if __name__ == "__main__":
    unittest.main()
