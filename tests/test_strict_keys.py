"""Тесты строгого режима ключей (SIA_STRICT_KEYS).

ДЫРА/РИСК, который закрывает этот файл
-------------------------------------
Если RECEIPT_SIGNING_KEY / JWT_SECRET_KEY / EVIDENCE_SIGNING_KEY не заданы,
сервис генерировал ЭФЕМЕРНЫЕ ключи и печатал предупреждение в stdout. В
контейнере stdout буферизуется/теряется, а тихая генерация означает: квитанции,
токены и подписи evidence НЕ ПЕРЕЖИВАЮТ рестарт — после деплоя/рестарта
подписанная доказательная база молча рассыпается.

Теперь есть SIA_STRICT_KEYS=1: отсутствие постоянных ключей — фатальная ошибка
старта (fail-fast), а не предупреждение. docker-compose.prod.yml выставляет
SIA_STRICT_KEYS=1 (defence-in-depth к обязательным ${VAR:?}).

Тесты подменяют sentinel.api.resolve_env, поэтому не зависят от реального
.env разработчика и не читают секреты.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import sentinel.api as api_module
from sentinel.api import _require_persistent_keys_if_strict

REQUIRED_KEYS = (
    "RECEIPT_SIGNING_KEY",
    "JWT_SECRET_KEY",
    "EVIDENCE_SIGNING_KEY",
)


class StrictKeysTestCase(unittest.TestCase):
    def _run(self, strict: bool, present: tuple[str, ...]) -> None:
        fake_resolve = lambda name: "value" if name in present else None  # noqa: E731
        with patch.object(api_module, "resolve_env", fake_resolve):
            _require_persistent_keys_if_strict(strict=strict)

    def test_disabled_strict_never_raises(self) -> None:
        # Без strict режима отсутствие ключей НЕ поднимает исключение
        # (иначе сломались бы dev/тестовые запуски).
        self._run(strict=False, present=())

    def test_strict_raises_when_all_keys_missing(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            self._run(strict=True, present=())
        message = str(ctx.exception)
        for name in REQUIRED_KEYS:
            self.assertIn(name, message)
        self.assertIn("SIA_STRICT_KEYS", message)

    def test_strict_raises_when_one_key_missing(self) -> None:
        present = ("RECEIPT_SIGNING_KEY", "JWT_SECRET_KEY")
        with self.assertRaises(RuntimeError) as ctx:
            self._run(strict=True, present=present)
        # Отсутствует только EVIDENCE_SIGNING_KEY.
        self.assertIn("EVIDENCE_SIGNING_KEY", str(ctx.exception))

    def test_strict_passes_when_all_keys_present(self) -> None:
        self._run(strict=True, present=REQUIRED_KEYS)

    def test_uses_correct_jwt_variable_name(self) -> None:
        """Строгий режим проверяет JWT_SECRET_KEY (как везде в проекте),
        а не ошибочное JWT_SECRET."""
        present = ("RECEIPT_SIGNING_KEY", "EVIDENCE_SIGNING_KEY")
        # JWT_SECRET_KEY отсутствует -> должно упасть (имя ключа верное).
        with self.assertRaises(RuntimeError) as ctx:
            self._run(strict=True, present=present)
        self.assertIn("JWT_SECRET_KEY", str(ctx.exception))

    def test_truthy_parsing(self) -> None:
        for raw in ("1", "TRUE", "True", "yes", "on", " on "):
            self.assertTrue(
                (raw.strip().lower() in ("1", "true", "yes", "on")), raw
            )
        for raw in ("0", "false", "no", "off", ""):
            self.assertFalse(
                (raw.strip().lower() in ("1", "true", "yes", "on")), raw
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
