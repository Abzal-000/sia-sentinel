"""Сторож окружения: тяжёлые зависимости должны импортироваться.

Урок маяка (мини-аудит 2026-08-22): ``from openai import OpenAI`` живёт
лениво внутри ``LLMFlowAuditor.__init__``, симулированный клиент до него не
доходит — и 583 зелёных теста сосуществовали с окружением, в котором
основная функция продукта (живой вызов) падала на import. Такие тесты
делают класс ошибки видимым сразу: сломанное/неполное окружение красит
сьют, а не ждёт первого живого прогона.
"""
from __future__ import annotations

import unittest
from pathlib import Path


class HeavyDependenciesImportTestCase(unittest.TestCase):
    def test_openai_imports(self) -> None:
        # Живые LLM-вызовы; требует httpx2 (жёсткая зависимость openai>=3)
        from openai import OpenAI  # noqa: F401

    def test_httpx2_imports(self) -> None:
        import httpx2  # noqa: F401

    def test_anthropic_imports(self) -> None:
        # Второй провайдер каталога; тот же класс ленивых импортов
        import anthropic  # noqa: F401

    def test_docker_sdk_imports(self) -> None:
        # SandboxExecutor; untyped-пакет, но отсутствие ломает код-путь CLI
        import docker  # noqa: F401


class PackageVersionConsistencyTestCase(unittest.TestCase):
    """sia.__version__ обязан совпадать с pyproject.toml.

    История: sia/__init__.py нёс 0.1.0 при pyproject 0.7.0 — версии
    разъехались незаметно, потому что никто не сверял. Один источник
    правды — pyproject; тест читает его же.
    """

    def test_sia_version_matches_pyproject(self) -> None:
        import tomllib

        import sia

        pyproject = (
            Path(__file__).resolve().parents[1] / "pyproject.toml"
        ).read_bytes()
        declared = tomllib.loads(pyproject.decode("utf-8"))["project"]["version"]
        self.assertEqual(sia.__version__, declared)


if __name__ == "__main__":
    unittest.main()
