"""Тесты корректной парной статистики Proof-of-Savings."""
from __future__ import annotations

import unittest

from sia.statistics import (
    holm_bonferroni,
    mcnemar_exact,
    minimum_detectable_difference,
    newcombe_paired_ci,
    non_inferiority_test,
    wilson_ci,
)


class WilsonCITestCase(unittest.TestCase):
    def test_all_successes(self) -> None:
        lower, upper = wilson_ci(10, 10, confidence=0.95)
        self.assertGreaterEqual(lower, 0.69)
        self.assertLessEqual(upper, 1.0)

    def test_zero_total(self) -> None:
        self.assertEqual(wilson_ci(0, 0), (0.0, 1.0))


class NewcombePairedCITestCase(unittest.TestCase):
    def test_no_discordance(self) -> None:
        # b=0, c=0: нет дискордантных пар, diff=0
        lower, upper = newcombe_paired_ci(0, 0, 20, confidence=0.95)
        self.assertLessEqual(lower, 0.0)
        self.assertGreaterEqual(upper, 0.0)

    def test_new_worse(self) -> None:
        # b=5 (старое прошло, новое упало), c=0: diff = -5/20 = -0.25
        lower, upper = newcombe_paired_ci(5, 0, 20, confidence=0.95)
        self.assertLess(lower, 0.0)
        self.assertLessEqual(upper, 0.0)

    def test_new_better(self) -> None:
        # b=0, c=5: diff = +0.25
        lower, upper = newcombe_paired_ci(0, 5, 20, confidence=0.95)
        self.assertGreaterEqual(lower, 0.0)
        self.assertGreater(upper, 0.0)

    def test_bounds_within_range(self) -> None:
        for b, c in [(0, 0), (3, 1), (1, 3), (10, 10)]:
            lower, upper = newcombe_paired_ci(b, c, 20, confidence=0.99)
            self.assertTrue(-1.0 <= lower <= upper <= 1.0)


class McNemarTestCase(unittest.TestCase):
    def test_no_discordance(self) -> None:
        self.assertEqual(mcnemar_exact(0, 0), 1.0)

    def test_symmetric(self) -> None:
        # b=c => p-value должен быть высоким (симметрия)
        p = mcnemar_exact(5, 5)
        self.assertGreater(p, 0.5)

    def test_asymmetric(self) -> None:
        # b=10, c=0 => сильная асимметрия, p-value низкий
        p = mcnemar_exact(10, 0)
        self.assertLess(p, 0.01)


class NonInferiorityTestCase(unittest.TestCase):
    def test_identical_results_non_inferior(self) -> None:
        old = [True] * 50
        new = [True] * 50
        result = non_inferiority_test(old, new, delta=0.10)
        self.assertTrue(result.non_inferior)
        self.assertEqual(result.verdict, "non_inferior")
        self.assertEqual(result.b, 0)
        self.assertEqual(result.c, 0)

    def test_slight_degradation_within_delta(self) -> None:
        # 4 из 200 упали (2%), delta=10% => неинфериорно
        # (при n=200 интервал достаточно узкий для подтверждения)
        old = [True] * 200
        new = [True] * 196 + [False] * 4
        result = non_inferiority_test(old, new, delta=0.10)
        self.assertTrue(result.non_inferior)

    def test_severe_degradation_inferior(self) -> None:
        # 15 из 50 упали (30%), delta=10% => инфериорно
        old = [True] * 50
        new = [True] * 35 + [False] * 15
        result = non_inferiority_test(old, new, delta=0.10)
        self.assertFalse(result.non_inferior)
        self.assertEqual(result.verdict, "inferior")

    def test_mdd_reported(self) -> None:
        old = [True] * 100
        new = [True] * 100
        result = non_inferiority_test(old, new, delta=0.05)
        self.assertGreater(result.mdd, 0.0)
        self.assertLess(result.mdd, 1.0)

    def test_mdd_uses_observed_discordance_when_above_assumption(self) -> None:
        # 30 из 100 пар дискордантны (30% > допущения 10%): опубликованный
        # MDD обязан характеризовать ЭТОТ прогон, а не гипотетический с 10%.
        # Раньше MDD молча считался по 0.10 и занижал слепоту аудита ровно
        # в том случае, когда дешёвая модель реально хуже.
        old = [True] * 85 + [False] * 15
        new = [True] * 55 + [False] * 45  # b=30, c=0

        result = non_inferiority_test(old, new, delta=0.10)

        expected = minimum_detectable_difference(
            100, alpha=0.05, power=0.80, p_discordant=0.30
        )
        self.assertAlmostEqual(result.mdd, expected, places=10)

        default_assumption = minimum_detectable_difference(
            100, alpha=0.05, power=0.80, p_discordant=0.10
        )
        self.assertGreater(result.mdd, default_assumption)

    def test_mdd_never_more_optimistic_than_assumption(self) -> None:
        # Наблюдённая дискордантность ниже допущения (2% < 10%): MDD
        # остаётся на полу-допущении — число не может стать оптимистичнее
        old = [True] * 196 + [False] * 4
        new = [True] * 200  # b=4, c=0

        result = non_inferiority_test(old, new, delta=0.10)

        expected = minimum_detectable_difference(
            200, alpha=0.05, power=0.80, p_discordant=0.10
        )
        self.assertAlmostEqual(result.mdd, expected, places=10)

    def test_mdd_respects_higher_explicit_assumption(self) -> None:
        # Явное допущение выше наблюдённого уважается как пол
        old = [True] * 196 + [False] * 4
        new = [True] * 200  # наблюдённая дискордантность 2%

        result = non_inferiority_test(
            old, new, delta=0.10, p_discordant_assumption=0.25
        )

        expected = minimum_detectable_difference(
            200, alpha=0.05, power=0.80, p_discordant=0.25
        )
        self.assertAlmostEqual(result.mdd, expected, places=10)

    def test_mismatched_lengths_raises(self) -> None:
        with self.assertRaises(ValueError):
            non_inferiority_test([True], [True, False], delta=0.1)

    def test_to_dict(self) -> None:
        old = [True] * 20
        new = [True] * 19 + [False]
        result = non_inferiority_test(old, new, delta=0.15)
        d = result.to_dict()
        self.assertIn("non_inferior", d)
        self.assertIn("minimum_detectable_difference", d)
        self.assertIn("mcnemar_p", d)


class HolmBonferroniTestCase(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(holm_bonferroni([]), [])

    def test_single_significant(self) -> None:
        decisions = holm_bonferroni([0.001, 0.5, 0.9], alpha=0.05)
        self.assertEqual(decisions, [True, False, False])

    def test_none_significant(self) -> None:
        decisions = holm_bonferroni([0.1, 0.2, 0.3], alpha=0.05)
        self.assertEqual(decisions, [False, False, False])

    def test_all_significant(self) -> None:
        decisions = holm_bonferroni([0.001, 0.002, 0.003], alpha=0.05)
        self.assertEqual(decisions, [True, True, True])

    def test_controls_fwer(self) -> None:
        # 20 кандидатов, все p=0.04: без поправки все бы прошли,
        # с Холмом только первый (0.04 <= 0.05/20=0.0025? нет) => ни один
        decisions = holm_bonferroni([0.04] * 20, alpha=0.05)
        self.assertEqual(sum(decisions), 0)


class MDDTestCase(unittest.TestCase):
    def test_larger_n_smaller_mdd(self) -> None:
        mdd_small = minimum_detectable_difference(50)
        mdd_large = minimum_detectable_difference(500)
        self.assertGreater(mdd_small, mdd_large)

    def test_zero_n(self) -> None:
        self.assertEqual(minimum_detectable_difference(0), 1.0)


if __name__ == "__main__":
    unittest.main()
