"""Валидация GitHub Actions workflow: YAML должен парситься GitHub-совместимо.

Пойманная в бою дыра (2026-09-24)
-------------------------------
Шаг с `name: Guard: requirements must stay cross-platform` содержал
НЕКАВЫЧЕЧНОЕ двоеточие внутри значения. YAML-сканер обрывается на этой
строке, GitHub помечает workflow как "workflow file issue" и НЕ СОЗДАЁТ ни
одного job — прогон падает с conclusion=failure, started_at пустым, нулём
jobs, и без единой строки лога. Локальные тесты это не ловили (тесты не
парсят workflow), поэтому 787 зелёных тестов ничего не говорили о CI.

Повторялась та же ошибка дважды подряд — ровно потому, что валидации не было.

Теперь она есть: каждый workflow обязан парситься PyYAML И содержать
минимальную структуру GitHub Actions (jobs → steps).
"""
from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml")) + sorted(
    (ROOT / ".github" / "workflows").glob("*.yaml")
)


class WorkflowYamlParsesTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(
            WORKFLOWS,
            "не найдено ни одного workflow в .github/workflows/",
        )

    def test_workflows_exist(self) -> None:
        self.assertGreaterEqual(len(WORKFLOWS), 2, "ожидались ci.yml и pages.yml")

    def test_every_workflow_parses_as_yaml(self) -> None:
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                try:
                    yaml.safe_load(path.read_text(encoding="utf-8"))
                except yaml.YAMLError as exc:
                    self.fail(
                        f"{path.name} не парсится GitHub-совместимым YAML: {exc}\n"
                        "Типичная причина — некавычечное двоеточие/двоеточие "
                        "в значении (например `name: Guard: text`). "
                        "Такой workflow не запускает ни одного job."
                    )

    def test_every_workflow_has_name_and_jobs(self) -> None:
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertIsInstance(data, dict, f"{path.name}: ожидался mapping")
                # Имя workflow: без name GitHub показывает путь файла вместо
                # читаемого названия в списке Actions.
                self.assertIn("name", data, f"{path.name}: нет поля name")
                self.assertIsInstance(data["name"], str)
                self.assertTrue(data["name"].strip())
                # GitHub отвергает workflow без jobs.
                self.assertIn("jobs", data, f"{path.name}: нет поля jobs")
                self.assertIsInstance(data["jobs"], dict)
                self.assertTrue(data["jobs"], f"{path.name}: jobs пуст")

    def test_every_step_has_run_or_uses(self) -> None:
        """Шаг обязан быть исполняемым: run: или uses:, иначе он ничего не делает."""
        for path in WORKFLOWS:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            for job_name, job in (data.get("jobs") or {}).items():
                steps = job.get("steps") or []
                for index, step in enumerate(steps):
                    with self.subTest(workflow=path.name, job=job_name, step=index):
                        self.assertIsInstance(step, dict)
                        has_action = "run" in step or "uses" in step
                        self.assertTrue(
                            has_action,
                            f"{path.name}/{job_name}: шаг без run/uses — "
                            "GitHub не сможет его выполнить",
                        )

    def test_step_names_do_not_contain_bare_colons(self) -> None:
        """Регрессия: name: Guard: X ломает YAML-сканер.

        GitHub Actions допускает двоеточие в name ТОЛЬКО в кавычках. Проверяем
        сырое значение: если двоеточие есть и кавычек нет — YAML не пройдёт.
        """
        offenders: list[str] = []
        for path in WORKFLOWS:
            for number, raw in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                stripped = raw.strip()
                if not stripped.startswith("- name:"):
                    continue
                value = stripped.split("name:", 1)[1].strip()
                if ":" in value and not (
                    value.startswith(('"', "'"))
                ):
                    offenders.append(f"{path.name}:{number}: {stripped}")
        self.assertEqual(
            offenders,
            [],
            "name: со значением через двоеточие без кавычек ломает YAML. "
            "Оберните в кавычки. Найдено:\n" + "\n".join(offenders),
        )


class CiWorkflowShapeTestCase(unittest.TestCase):
    """Точечные ожидания по CI: гард зависимостей обязан быть на месте."""

    def setUp(self) -> None:
        self.ci_path = ROOT / ".github" / "workflows" / "ci.yml"
        self.data = yaml.safe_load(self.ci_path.read_text(encoding="utf-8"))

    def test_requirements_guard_step_exists(self) -> None:
        steps = self.data["jobs"]["test"]["steps"]
        names = [str(s.get("name", "")) for s in steps]
        self.assertTrue(
            any("cross-platform" in n for n in names),
            "в CI пропала проверка кросс-платформенности requirements.txt — "
            f"шаги: {names}",
        )

    def test_guard_runs_before_install(self) -> None:
        """Гард обязан стоять ДО установки, иначе он не защищает."""
        names = [str(s.get("name", "")) for s in self.data["jobs"]["test"]["steps"]]
        guard = next(
            (i for i, n in enumerate(names) if "cross-platform" in n), None
        )
        install = next(
            (i for i, n in enumerate(names) if n == "Install dependencies"), None
        )
        self.assertIsNotNone(guard)
        self.assertIsNotNone(install)
        self.assertLess(guard, install, "гард должен идти до установки зависимостей")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
