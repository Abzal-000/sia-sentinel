from __future__ import annotations

import unittest

from sia.evaluation_engine import EvaluationEngine


class SemanticEquivalenceSuiteTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = EvaluationEngine(performance_iterations=10, performance_repeat=1)

    def test_suite_all_pass(self) -> None:
        old_code = "def add(a, b):\n    return a + b\n"
        new_code = "def add(a, b):\n    return b + a\n"
        suite = [
            "assert add(1, 2) == 3",
            "assert add(-1, 1) == 0",
        ]

        result = self.engine.check_semantic_equivalence_suite(old_code, new_code, suite)

        self.assertTrue(result["equivalent"])
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["passed_old"], 2)
        self.assertEqual(result["passed_new"], 2)

    def test_suite_new_fails(self) -> None:
        old_code = "def add(a, b):\n    return a + b\n"
        new_code = "def add(a, b):\n    return a * b\n"
        suite = ["assert add(2, 3) == 5"]

        result = self.engine.check_semantic_equivalence_suite(old_code, new_code, suite)

        self.assertFalse(result["equivalent"])
        self.assertEqual(result["failed_new"], suite)
        self.assertEqual(result["new_only_failures"], suite)

    def test_suite_old_fails(self) -> None:
        old_code = "def add(a, b):\n    return a - b\n"
        new_code = "def add(a, b):\n    return a + b\n"
        suite = ["assert add(2, 3) == 5"]

        result = self.engine.check_semantic_equivalence_suite(old_code, new_code, suite)

        self.assertFalse(result["equivalent"])
        self.assertEqual(result["failed_old"], suite)

    def test_empty_suite_not_equivalent(self) -> None:
        result = self.engine.check_semantic_equivalence_suite("x = 1", "x = 1", [])

        self.assertFalse(result["equivalent"])
        self.assertEqual(result["total"], 0)
