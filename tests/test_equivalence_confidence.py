from __future__ import annotations

import unittest

from sia.evaluation_engine import EvaluationEngine, wilson_confidence_interval
from sia.models import EquivalenceReport


class WilsonIntervalTestCase(unittest.TestCase):
    def test_all_successes(self) -> None:
        lower, upper = wilson_confidence_interval(10, 10, confidence=0.95)

        self.assertGreaterEqual(lower, 0.69)  # 10/10 -> нижняя граница ~0.7
        self.assertLessEqual(upper, 1.0)

    def test_no_successes(self) -> None:
        lower, upper = wilson_confidence_interval(0, 10, confidence=0.95)

        self.assertEqual(lower, 0.0)
        self.assertLess(upper, 0.31)

    def test_zero_total(self) -> None:
        lower, upper = wilson_confidence_interval(0, 0)

        self.assertEqual((lower, upper), (0.0, 1.0))

    def test_higher_confidence_widens_interval(self) -> None:
        narrow = wilson_confidence_interval(8, 10, confidence=0.90)
        wide = wilson_confidence_interval(8, 10, confidence=0.99)

        self.assertLessEqual(wide[0], narrow[0])
        self.assertGreaterEqual(wide[1], narrow[1])

    def test_bounds_within_unit_range(self) -> None:
        for successes in (0, 3, 7, 10):
            lower, upper = wilson_confidence_interval(successes, 10, confidence=0.99)
            self.assertTrue(0.0 <= lower <= upper <= 1.0)


class EquivalenceWithConfidenceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = EvaluationEngine(performance_iterations=10, performance_repeat=1)

    def test_equivalent_pair_report(self) -> None:
        old_code = "def add(a, b):\n    return a + b\n"
        new_code = "def add(a, b):\n    return b + a\n"
        suite = ["assert add(2, 3) == 5", "assert add(0, 0) == 0"]

        report = self.engine.check_equivalence_with_confidence(old_code, new_code, suite)

        self.assertIsInstance(report, EquivalenceReport)
        self.assertTrue(report.equivalent)
        self.assertEqual(report.verdict, "equivalent")
        self.assertEqual(report.total, 2)
        self.assertGreater(report.ci_lower, 0.3)
        self.assertLessEqual(report.ci_upper, 1.0)

    def test_degraded_pair_report(self) -> None:
        old_code = "def add(a, b):\n    return a + b\n"
        new_code = "def add(a, b):\n    return a * b\n"
        suite = ["assert add(2, 3) == 5"]

        report = self.engine.check_equivalence_with_confidence(old_code, new_code, suite)

        self.assertFalse(report.equivalent)
        self.assertEqual(report.verdict, "degraded")
        self.assertEqual(report.ci_lower, 0.0)

    def test_legacy_dict_keys_preserved(self) -> None:
        old_code = "def add(a, b):\n    return a + b\n"
        suite = ["assert add(1, 1) == 2"]

        result = self.engine.check_semantic_equivalence_suite(old_code, old_code, suite)

        for key in (
            "equivalent",
            "total",
            "passed_old",
            "passed_new",
            "failed_old",
            "failed_new",
            "new_only_failures",
            "pass_rate_old",
            "pass_rate_new",
        ):
            self.assertIn(key, result)

        self.assertIn("ci_lower", result)
        self.assertIn("ci_upper", result)
        self.assertIn("confidence_level", result)
        self.assertIn("verdict", result)

    def test_repetitions_aggregate(self) -> None:
        old_code = "def add(a, b):\n    return a + b\n"
        suite = ["assert add(1, 1) == 2"]

        report = self.engine.check_equivalence_with_confidence(
            old_code,
            old_code,
            suite,
            repetitions=3,
        )

        self.assertEqual(report.repetitions, 3)
        self.assertTrue(report.equivalent)

    def test_repetitions_do_not_inflate_trials(self) -> None:
        # B4a: повторения не создают независимых испытаний —
        # CI строится по числу тестов, а не тестов*повторений
        old_code = "def add(a, b):\n    return a + b\n"
        suite = ["assert add(1, 1) == 2", "assert add(2, 2) == 4"]

        single = self.engine.check_equivalence_with_confidence(
            old_code, old_code, suite, repetitions=1
        )
        repeated = self.engine.check_equivalence_with_confidence(
            old_code, old_code, suite, repetitions=5
        )

        self.assertEqual(single.ci_lower, repeated.ci_lower)
        self.assertEqual(single.ci_upper, repeated.ci_upper)

    def test_confidence_level_reports_effective_level(self) -> None:
        # B4b: нестандартный уровень → отчёт показывает фактически
        # использованный (ближайший известный), а не запрошенный
        old_code = "def add(a, b):\n    return a + b\n"
        suite = ["assert add(1, 1) == 2"]

        report = self.engine.check_equivalence_with_confidence(
            old_code, old_code, suite, confidence=0.97
        )

        self.assertEqual(report.confidence_level, 0.95)

        exact = self.engine.check_equivalence_with_confidence(
            old_code, old_code, suite, confidence=0.99
        )
        self.assertEqual(exact.confidence_level, 0.99)


if __name__ == "__main__":
    unittest.main()
