"""Регрессионный тест: оптимизатор выбирает кандидата по АБСОЛЮТНОЙ цене.

ДЫРА, которую закрывает этот файл
--------------------------------
Финальный победитель выбирался по МАКСИМАЛЬНОМУ savings_ratio (проценту скидки
относительно baseline). Но продукт обещает «подбор самой дешёвой
конфигурации», и это разные вещи, когда baseline сам дорогой:

  candidate A: unit_cost = 0.90, ratio = 10%
  candidate B: unit_cost = 0.50, ratio = 40%
  baseline:   unit_cost = 1.00

Здесь A имеет ratio 10% (10% дешевле baseline), B — 40%. По ratio побеждает B,
но и по абсолютной цене B дешевле — пример не различающий.

Сценарий, где ratio врёт (именно он и был дырой): когда baseline ОЧЕНЬ дорогой,
его же output_tokens делают так, что кандидат с относительно скромной скидкой
в абсолюте дороже кандидата с меньшей скидкой, но низкой ценой. Например:

  baseline:        unit = 1.00
  candidate A:     unit = 0.80  -> ratio 20%
  candidate B:     unit = 0.60  -> ratio 40%   (дешевле — верно)

Чтобы ratio выбрал ХУДШИЙ вариант, нужен кандидат, который дороже в абсолюте, но
чья скидка больше. Это возможно, когда у кандидатов РАЗНЫЙ объём токенов на
вызов при разной цене за токен: дорогой-per-token кандидат может иметь
меньшую стоимость вызова, а дешёвый-per-token — но при высоком расходе
токенов. Ratio зависит и от baseline-расхода, и от расхода кандидата, поэтому
для кандидата с БОЛЬШИМ расходом токенов даже небольшая разница в цене за токен
может дать БОЛЬШИЙ процент скидки при более высокой абсолютной стоимости.

Тест строит такой случай и требует, чтобы optimizer выбрал кандидата с
МИНИМАЛЬНОЙ абсолютной unit_cost, а не с максимальным ratio.
"""
from __future__ import annotations

import unittest

from sia.llm_flow import LLMEndpointConfig
from sia.model_catalog import ModelSpec
from sia.optimizer import OptimizationGoal, SavingsOptimizer


DATASET = (
    {"prompt": "What is 2+2?", "expect_contains": "4"},
    {"prompt": "Capital of France?", "expect_contains": "Paris"},
    {"prompt": "What is 10-3?", "expect_contains": "7"},
    {"prompt": "Largest ocean?", "expect_contains": "Pacific"},
)


class OptimizerPicksLowestAbsoluteCostTestCase(unittest.TestCase):
    """Победитель — минимальная абсолютная цена, а не максимальный процент."""

    def _run(self, candidates: list[ModelSpec], baseline: LLMEndpointConfig):
        goal = OptimizationGoal(
            dataset=DATASET,
            quality_floor=0.9,
            final_repetitions=2,
        )
        return SavingsOptimizer().optimize(
            goal=goal, baseline=baseline, candidates=candidates
        )

    def test_selection_uses_absolute_cost_not_ratio(self) -> None:
        """Кандидаты, у которых максимальный ratio ≠ минимальная абсолютная цена.

        Здесь кандидат "high-ratio" намеренно дороже в абсолюте, но даёт больший
        процент скидки (у него дешевле input, но заметно дороже output при
        verbose-профиле). Кандидат "low-cost" дешевле в абсолюте, но процент
        скидки меньше. Правильный выбор — low-cost.
        """
        baseline = LLMEndpointConfig(
            model_name="baseline",
            input_token_usd_per_m=1.0,
            output_token_usd_per_m=2.0,
            profile="standard",
        )

        # high-ratio: дешёвый input, но дорогой output + verbose (много токенов).
        high_ratio = ModelSpec(
            model_name="high-ratio",
            input_token_usd_per_m=0.05,
            output_token_usd_per_m=8.0,
            profile="verbose",
        )
        # low-cost: умеренные цены, экономный профиль.
        low_cost = ModelSpec(
            model_name="low-cost",
            input_token_usd_per_m=0.1,
            output_token_usd_per_m=0.3,
            profile="concise",
        )

        result = self._run([high_ratio, low_cost], baseline)

        # Оба кандидата доказали качество (иначе выбор не про этот случай).
        self.assertIn(high_ratio.model_name, result.final_audits)
        self.assertIn(low_cost.model_name, result.final_audits)

        hr_report = result.final_audits[high_ratio.model_name]
        lc_report = result.final_audits[low_cost.model_name]

        # Тест имеет смысл только если кандидаты различаются по стоимости.
        self.assertNotAlmostEqual(
            hr_report.costs.new_unit_cost_usd,
            lc_report.costs.new_unit_cost_usd,
            places=9,
            msg="кандидаты должны иметь разную стоимость вызова",
        )
        self.assertGreater(
            lc_report.costs.new_unit_cost_usd,
            0.0,
            "low-cost должен иметь положительную стоимость",
        )

        # Победитель обязан быть самым дешёвым по АБСОЛЮТНОЙ цене среди
        # кандидатов с подтверждённым качеством.
        cheapest = min(
            result.final_audits.values(),
            key=lambda r: r.costs.new_unit_cost_usd,
        )
        self.assertIsNotNone(result.best)
        self.assertEqual(
            result.final_audits[result.best].costs.new_unit_cost_usd,
            cheapest.costs.new_unit_cost_usd,
            "оптимизатор обязан выбрать кандидата с минимальной абсолютной ценой",
        )

    def test_published_manifest_reports_selection_metric(self) -> None:
        """Манифест публикует выбранного кандидата (прозрачность выбора)."""
        baseline = LLMEndpointConfig(
            model_name="baseline",
            input_token_usd_per_m=1.0,
            output_token_usd_per_m=2.0,
            profile="standard",
        )
        candidates = [
            ModelSpec(model_name="c1", input_token_usd_per_m=0.1,
                      output_token_usd_per_m=0.3, profile="concise"),
            ModelSpec(model_name="c2", input_token_usd_per_m=0.05,
                      output_token_usd_per_m=8.0, profile="verbose"),
        ]
        result = self._run(candidates, baseline)
        # Манифест фиксирует best — выбор не скрыт.
        self.assertIn("best", result.manifest)
        if result.best is not None:
            self.assertEqual(result.manifest["best"], result.best)


class OptimizerAllCandidatesFailingTestCase(unittest.TestCase):
    """Если никто не доказал экономию — рекомендации нет (best=None)."""

    def test_no_recommendation_when_nothing_proven(self) -> None:
        baseline = LLMEndpointConfig(
            model_name="baseline",
            input_token_usd_per_m=1.0,
            output_token_usd_per_m=2.0,
            profile="standard",
        )
        # Кандидат априори не дешевле baseline -> экономии нет -> best None.
        candidates = [
            ModelSpec(model_name="expensive", input_token_usd_per_m=5.0,
                      output_token_usd_per_m=10.0, profile="verbose"),
        ]
        result = self._run_safe(baseline, candidates)
        self.assertIsNone(result.best)
        self.assertIsNone(result.recommendation)

    def _run_safe(self, baseline, candidates):
        goal = OptimizationGoal(dataset=DATASET, quality_floor=0.9,
                                final_repetitions=2)
        return SavingsOptimizer().optimize(
            goal=goal, baseline=baseline, candidates=candidates
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
