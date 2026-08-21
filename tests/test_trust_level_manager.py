from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sia.models import Task, TrustLevel
from sia.trust_level_manager import TrustLevelManager


class TrustLevelManagerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)

        self.function_code = "def foo():\n    return 1\n"
        self.target_path = self.workspace / "target.py"
        self.target_path.write_text(self.function_code, encoding="utf-8")

        self.manager = TrustLevelManager(level=TrustLevel.NOVICE)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_task(
        self,
        target_path=None,
        current_code=None,
        target_symbol=None,
        allowed_paths=None,
    ) -> Task:
        return Task(
            description="Test task",
            target_path=str(target_path or self.target_path),
            current_code=current_code or self.function_code,
            target_symbol=target_symbol or "foo",
            allowed_paths=tuple(allowed_paths or (str(self.workspace),)),
        )

    def test_function_modification_allowed_for_novice(self) -> None:
        task = self._make_task()
        decision = self.manager.can_modify(task)

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.current_level, TrustLevel.NOVICE)

    def test_string_def_in_comment_is_not_function(self) -> None:
        code = "# def fake(): pass\n"
        self.target_path.write_text(code, encoding="utf-8")

        task = self._make_task(
            current_code=code,
            target_symbol=None,
        )

        decision = self.manager.can_modify(task)
        self.assertFalse(decision.allowed)

    def test_path_traversal_denied(self) -> None:
        evil_path = self.workspace / ".." / "secret.py"

        task = self._make_task(target_path=evil_path)
        decision = self.manager.can_modify(task)

        self.assertFalse(decision.allowed)

    def test_class_denied_for_novice(self) -> None:
        code = "class Foo:\n    pass\n"
        self.target_path.write_text(code, encoding="utf-8")

        task = self._make_task(
            current_code=code,
            target_symbol="Foo",
        )

        decision = self.manager.can_modify(task)
        self.assertFalse(decision.allowed)

    def test_class_allowed_for_junior(self) -> None:
        manager = TrustLevelManager(level=TrustLevel.JUNIOR)

        code = "class Foo:\n    pass\n"
        self.target_path.write_text(code, encoding="utf-8")

        task = self._make_task(
            current_code=code,
            target_symbol="Foo",
        )

        decision = manager.can_modify(task)
        self.assertTrue(decision.allowed)

    def test_promotion_after_successes(self) -> None:
        task = self._make_task()

        for _ in range(3):
            self.manager.record_success(task)

        self.assertEqual(self.manager.level, TrustLevel.INTERN)

    def test_demotion_after_failures(self) -> None:
        manager = TrustLevelManager(level=TrustLevel.JUNIOR)
        task = self._make_task()

        for _ in range(2):
            manager.record_failure(task, "benchmark failed")

        self.assertEqual(manager.level, TrustLevel.INTERN)
