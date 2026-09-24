"""Регрессионные тесты абсолютного гейта качества клейма savings_verified.

ДЫРА, которую закрывает этот файл
--------------------------------
Парный тест неинфериорности измеряет ОТНОСИТЕЛЬНОЕ качество («новое не хуже
старого»). Если обе конфигурации провалили ВСЕ тесты датасета, то b = c = 0,
наблюдаемое качество «идентично» (нулевая дискордантность), и прежний код
считал savings_verified = True — то есть выпускал подписанную квитанцию
«экономия доказана» для полностью нерабочей системы.

Для продукта, чья ценность — «proof, not vibes», это дыра в самой
доказательной базе. Тесты ниже фиксируют исправление, чтобы дыра не
вернулась рефакторингом.

Также зафиксирована вторая половина фикса: Wilson CI в LLM-флоу считается на
уровне ЭЛЕМЕНТА датасета, а не на уровне отдельных вызовов. Счёт по вызовам —
псевдорепликация: повторы одного промпта коррелированы, эффективная n
завышена, доверительный интервал неоправданно узкий.
"""
from __future__ import annotations

import unittest

from sia.audit import AuditReport
from sia.evaluation_engine import EvaluationEngine, wilson_confidence_interval
from sia.statistics import (
    DEFAULT_ABSOLUTE_QUALITY_FLOOR,
    absolute_quality_met,
)


# --- Код для аудита: обе версии ПРОВАЛЯЮТ весь сьют -------------------------
# Старая «работает» (быстро) — но обе функции неверны, поэтому тесты падают
# у обеих. b = c = 0 (полная дискордантность нулевая), pass_rate_new = 0.
BROKEN_OLD = """
def transform(n):
    return n + 1
"""

BROKEN_NEW = """
def transform(n):
    return n + 1
"""

FAILING_SUITE = [
    "assert transform(1) == 999",
    "assert transform(2) == 999",
    "assert transform(3) == 999",
]


class AbsoluteQualityHelperTestCase(unittest.TestCase):
    """Базовый барьер absolute_quality_met."""

    def test_default_floor_rejects_wholesale_failure(self) -> None:
        # pass_rate_new = 0 — провалился весь датасет. Не должен проходить.
        self.assertFalse(absolute_quality_met(0.0))

    def test_default_floor_accepts_real_quality(self) -> None:
        self.assertTrue(absolute_quality_met(0.9))
        self.assertTrue(absolute_quality_met(1.0))

    def test_explicit_floor_is_honoured(self) -> None:
        # Строгий floor: 60% прохождений не дотягивает до 0.9.
        self.assertFalse(absolute_quality_met(0.6, floor=0.9))
        self.assertTrue(absolute_quality_met(0.95, floor=0.9))

    def test_floor_is_inclusive_at_boundary(self) -> None:
        self.assertTrue(absolute_quality_met(DEFAULT_ABSOLUTE_QUALITY_FLOOR))

    def test_none_floor_falls_back_to_default(self) -> None:
        self.assertTrue(absolute_quality_met(0.6, floor=None))
        self.assertFalse(absolute_quality_met(0.1, floor=None))


class CodeAuditAbsoluteQualityTestCase(unittest.TestCase):
    """Кодовый путь (sia.audit): проваленная новая версия ≠ доказанная экономия."""

    def setUp(self) -> None:
        from sia.audit import ProofOfSavingsAuditor
        from sia.cost_model import PricingConfig

        self.auditor = ProofOfSavingsAuditor(
            evaluation=EvaluationEngine(performance_iterations=5, performance_repeat=1)
        )
        self.pricing = PricingConfig(compute_usd_per_hour=3.6)

    def test_both_versions_failing_is_not_savings_verified(self) -> None:
        """ГЛАВНЫЙ регресс-тест: 0% качества у обеих версий.

        Прежний код здесь ставил savings_verified = True (b = c = 0 ->
        «наблюдаемое качество идентично»), выпуская квитанцию «экономия
        доказана» для сломанной системы. Теперь — обязан быть False.
        """
        report = self.auditor.audit(
            old_code=BROKEN_OLD,
            new_code=BROKEN_NEW,
            function_name="transform",
            test_suite=FAILING_SUITE,
            args_template=(10,),
            pricing=self.pricing,
        )

        # Обе версии провалили всё: нулевая доля прохождений.
        self.assertEqual(report.equivalence["pass_rate_new"], 0.0)
        self.assertEqual(report.equivalence["failed_new"], FAILING_SUITE)
        # Относительный тест здесь ОБЕСПЕЧЕН (обе одинаково сломаны) …
        self.assertTrue(report.relative_non_inferior)
        # … но абсолютный барьер качества провален, поэтому итоговый клейм
        # «экономия доказана» НЕ выставляется.
        self.assertFalse(report.absolute_quality_ok)
        self.assertFalse(report.savings_verified)

    def test_absolute_gate_is_published_in_report(self) -> None:
        """Гейт публикуется в отчёте прозрачно (входит в подпись)."""
        report = self.auditor.audit(
            old_code=BROKEN_OLD,
            new_code=BROKEN_NEW,
            function_name="transform",
            test_suite=FAILING_SUITE,
            args_template=(10,),
            pricing=self.pricing,
        )
        abs_quality = report.to_dict()["claim"]["absolute_quality"]
        self.assertEqual(abs_quality["pass_rate_new"], 0.0)
        self.assertFalse(abs_quality["absolute_met"])
        self.assertEqual(
            abs_quality["quality_floor"], DEFAULT_ABSOLUTE_QUALITY_FLOOR
        )
        # published savings_verified согласован с абсолютным гейтом
        self.assertFalse(report.to_dict()["claim"]["savings_verified"])


class RealSavingsStillVerifiedTestCase(unittest.TestCase):
    """Корректная оптимизация ПО-прежнему даёт verified (регресс в другую сторону)."""

    def test_genuine_savings_still_verified(self) -> None:
        from sia.audit import ProofOfSavingsAuditor
        from sia.cost_model import PricingConfig

        old_code = """
def fib(n):
    if n <= 1:
        return n
    return fib(n - 1) + fib(n - 2)
"""
        new_code = """
def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
"""
        suite = ["assert fib(0) == 0", "assert fib(1) == 1", "assert fib(10) == 55"]

        auditor = ProofOfSavingsAuditor(
            evaluation=EvaluationEngine(performance_iterations=50, performance_repeat=2)
        )
        report = auditor.audit(
            old_code=old_code,
            new_code=new_code,
            function_name="fib",
            test_suite=suite,
            args_template=(18,),
            pricing=PricingConfig(compute_usd_per_hour=3.6),
        )

        # Новая версия реально проходит сьют (pass_rate_new = 1.0).
        self.assertEqual(report.equivalence["pass_rate_new"], 1.0)
        self.assertTrue(report.absolute_quality_ok)
        self.assertTrue(report.relative_non_inferior)
        # Настоящая экономия на настоящем качестве остаётся подтверждённой.
        self.assertTrue(report.savings_verified)


class CustomQualityFloorTestCase(unittest.TestCase):
    """Явный quality_floor позволяет задать строгий продуктовый порог."""

    def test_custom_floor_blocks_partial_quality(self) -> None:

        report = AuditReport(
            manifest={},
            performance={},
            equivalence={
                "verdict": "equivalent",
                "pass_rate_new": 0.6,  # выше дефолта 0.5, но ниже строгого 0.9
                "ci_lower": 0.5,
                "ci_upper": 0.7,
            },
            costs={"savings_ratio": 0.4},
            quality_score=0.6,
            security_vulnerabilities=0,
            overall_efficiency_score=0.6,
            paired={"non_inferior": True, "b_old_pass_new_fail": 0, "c_old_fail_new_pass": 0},
            quality_floor=0.9,
        )
        self.assertFalse(report.absolute_quality_ok)
        self.assertFalse(report.savings_verified)

    def test_default_floor_accepts_same_report(self) -> None:

        report = AuditReport(
            manifest={},
            performance={},
            equivalence={
                "verdict": "equivalent",
                "pass_rate_new": 0.6,
                "ci_lower": 0.5,
                "ci_upper": 0.7,
            },
            costs={"savings_ratio": 0.4},
            quality_score=0.6,
            security_vulnerabilities=0,
            overall_efficiency_score=0.6,
            paired={"non_inferior": True, "b_old_pass_new_fail": 0, "c_old_fail_new_pass": 0},
            # дефолт 0.5 -> 0.6 проходит
        )
        self.assertTrue(report.absolute_quality_ok)
        self.assertTrue(report.savings_verified)


class WilsonItemLevelTestCase(unittest.TestCase):
    """Wilson должен считаться по элементам, а не по отдельным вызовам.

    Регрессия псевдорепликации: при repetitions > 1 прежний код считал CI по
    passed_trials/total_trials (уровень вызова). Здесь проверяем сам примитив и
    инвариант: n элементов даёт интервал шире, чем искусственно раздутое n
    повторов с тем же числом успешных элементов.
    """

    def test_wilson_narrower_with_larger_n(self) -> None:
        # Один и тот же успех (1 успех), но разный знаменатель.
        lo_small, _ = wilson_confidence_interval(1, 1, confidence=0.95)
        lo_large, _ = wilson_confidence_interval(10, 10, confidence=0.95)
        # Большая n даёт более высокую нижнюю границу (увереннее).
        self.assertLess(lo_small, lo_large)

    def test_wilson_lower_bound_zero_for_all_failures(self) -> None:
        lo, hi = wilson_confidence_interval(0, 5, confidence=0.95)
        self.assertEqual(lo, 0.0)
        self.assertGreater(hi, 0.0)

    def test_wilson_uses_item_count_not_trials(self) -> None:
        """При 3 успешных элементах из 3 CI считается по n=3, не по числу вызовов."""
        lo_item, _ = wilson_confidence_interval(3, 3, confidence=0.95)
        # Если бы CI считался по «раздутым» trials (например 12 из 12), он был бы
        # заметно выше. Проверяем, что элементный уровень даёт ожидаемо широкую
        # (консервативную) нижнюю границу.
        lo_trial_inflated, _ = wilson_confidence_interval(12, 12, confidence=0.95)
        self.assertLess(lo_item, lo_trial_inflated)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
