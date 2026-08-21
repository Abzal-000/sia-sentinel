from __future__ import annotations

import unittest

from sia.llm_flow import CompletionResult, LLMEndpointConfig, SimulatedLLMClient
from sia.model_catalog import ModelSpec
from sia.optimizer import (
    OPTIMIZATION_PROTOCOL,
    OptimizationGoal,
    SavingsOptimizer,
    spec_to_endpoint,
)

DATASET = tuple(
    {"label": f"case-{i}", "prompt": f"Question {i}?", "expect_contains": f"answer-{i}"}
    for i in range(4)
)

BASELINE = LLMEndpointConfig(
    model_name="premium-baseline",
    input_token_usd_per_m=3.0,
    output_token_usd_per_m=15.0,
    profile="verbose",
)

CANDIDATES = [
    ModelSpec(model_name="mid-model", tier="mid",
              input_token_usd_per_m=0.6, output_token_usd_per_m=1.8),
    ModelSpec(model_name="economy-model", tier="economy",
              input_token_usd_per_m=0.1, output_token_usd_per_m=0.4),
]


class FailingClient:
    """Клиент, который всегда отвечает мимо чекера."""

    def complete(self, prompt: str, expect=None) -> CompletionResult:
        return CompletionResult(
            text="totally wrong answer",
            input_tokens=10,
            output_tokens=10,
            latency_sec=0.01,
        )


class BrokenClient:
    """Клиент, который падает при каждом вызове (недоступный эндпоинт)."""

    def complete(self, prompt: str, expect=None) -> CompletionResult:
        raise RuntimeError("404 Not Found: model unavailable")


def _factory_with_bad_model(config: LLMEndpointConfig):
    if config.model_name == "bad-model":
        return FailingClient()
    return SimulatedLLMClient(config)


def _factory_with_broken_endpoint(config: LLMEndpointConfig):
    if config.model_name == "broken-endpoint":
        return BrokenClient()
    return SimulatedLLMClient(config)


class OptimizationGoalTestCase(unittest.TestCase):
    def test_empty_dataset_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OptimizationGoal(dataset=())

    def test_invalid_quality_floor_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OptimizationGoal(dataset=DATASET, quality_floor=0.0)

        with self.assertRaises(ValueError):
            OptimizationGoal(dataset=DATASET, quality_floor=1.5)

    def test_screening_dataset_is_deterministic_subsample(self) -> None:
        goal = OptimizationGoal(dataset=DATASET, screening_fraction=0.5)

        first = goal.screening_dataset()
        second = goal.screening_dataset()

        self.assertEqual(first, second)
        self.assertEqual(len(first), 2)
        self.assertTrue(all(item in DATASET for item in first))

    def test_screening_fraction_one_returns_full_dataset(self) -> None:
        goal = OptimizationGoal(dataset=DATASET, screening_fraction=1.0)

        self.assertEqual(goal.screening_dataset(), DATASET)


class SpecToEndpointTestCase(unittest.TestCase):
    def test_tier_maps_to_simulated_profile(self) -> None:
        premium = spec_to_endpoint(ModelSpec(
            model_name="p", tier="premium",
            input_token_usd_per_m=1.0, output_token_usd_per_m=3.0,
        ))
        economy = spec_to_endpoint(ModelSpec(
            model_name="e", tier="economy",
            input_token_usd_per_m=0.1, output_token_usd_per_m=0.3,
        ))

        self.assertEqual(premium.profile, "verbose")
        self.assertEqual(economy.profile, "concise")

    def test_api_key_not_embedded(self) -> None:
        endpoint = spec_to_endpoint(ModelSpec(
            model_name="m", api_key_env="SOME_KEY_ENV",
            input_token_usd_per_m=1.0, output_token_usd_per_m=3.0,
        ))

        self.assertNotIn("api_key", endpoint.public_dict())


class SavingsOptimizerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.goal = OptimizationGoal(
            dataset=DATASET,
            quality_floor=0.9,
            final_repetitions=2,
        )
        self.optimizer = SavingsOptimizer()

    def test_picks_cheapest_quality_preserving_candidate(self) -> None:
        result = self.optimizer.optimize(
            goal=self.goal, baseline=BASELINE, candidates=CANDIDATES
        )

        self.assertEqual(result.best, "economy-model")

        rec = result.recommendation
        self.assertIsNotNone(rec)
        self.assertTrue(rec["savings_verified"])
        self.assertGreater(rec["savings_ratio"], 0.5)
        self.assertEqual(rec["model_name"], "economy-model")

    def test_final_audits_are_full_reports(self) -> None:
        result = self.optimizer.optimize(
            goal=self.goal, baseline=BASELINE, candidates=CANDIDATES
        )

        self.assertEqual(set(result.final_audits), set(result.finalists))

        for report in result.final_audits.values():
            self.assertEqual(report.mode, "simulated")
            self.assertEqual(report.manifest["dataset_size"], len(DATASET))

    def test_failing_candidate_eliminated_at_screening(self) -> None:
        optimizer = SavingsOptimizer(client_factory=_factory_with_bad_model)
        candidates = CANDIDATES + [
            ModelSpec(model_name="bad-model", tier="economy",
                      input_token_usd_per_m=0.01, output_token_usd_per_m=0.01),
        ]

        result = optimizer.optimize(
            goal=self.goal, baseline=BASELINE, candidates=candidates
        )

        bad = [ev for ev in result.evaluations if ev.model_name == "bad-model"]
        self.assertTrue(bad)
        self.assertTrue(bad[0].eliminated)
        self.assertIn("quality floor", bad[0].reason)

        # Самый дешёвый кандидат отброшен — побеждает следующий по цене
        self.assertEqual(result.best, "economy-model")
        self.assertNotIn("bad-model", result.finalists)

    def test_max_finalists_cut_keeps_cheapest(self) -> None:
        goal = OptimizationGoal(
            dataset=DATASET, quality_floor=0.9, max_finalists=1,
        )
        candidates = CANDIDATES + [
            ModelSpec(model_name="pricier-economy", tier="economy",
                      input_token_usd_per_m=0.2, output_token_usd_per_m=0.8),
        ]

        result = self.optimizer.optimize(
            goal=goal, baseline=BASELINE, candidates=candidates
        )

        self.assertEqual(result.finalists, ("economy-model",))

        cut = [
            ev for ev in result.evaluations
            if ev.model_name == "pricier-economy" and ev.eliminated
        ]
        self.assertTrue(cut)
        self.assertIn("cut", cut[0].reason)

    def test_baseline_among_candidates_rejected(self) -> None:
        candidates = CANDIDATES + [
            ModelSpec(model_name="premium-baseline", tier="premium",
                      input_token_usd_per_m=3.0, output_token_usd_per_m=15.0),
        ]

        with self.assertRaises(ValueError):
            self.optimizer.optimize(
                goal=self.goal, baseline=BASELINE, candidates=candidates
            )

    def test_empty_candidates_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.optimizer.optimize(goal=self.goal, baseline=BASELINE, candidates=[])

    def test_result_dict_structure(self) -> None:
        result = self.optimizer.optimize(
            goal=self.goal, baseline=BASELINE, candidates=CANDIDATES
        )
        data = result.to_dict()

        self.assertEqual(data["protocol"], OPTIMIZATION_PROTOCOL)
        self.assertEqual(data["goal"]["dataset_size"], len(DATASET))
        self.assertEqual(data["baseline"]["model_name"], "premium-baseline")
        self.assertIsInstance(data["candidates"], list)
        self.assertIsInstance(data["final_audits"], dict)
        self.assertIn("dataset_sha256", data["manifest"])
        self.assertEqual(data["manifest"]["best"], "economy-model")
        self.assertEqual(data["recommendation"]["model_name"], "economy-model")

    def test_no_recommendation_when_nothing_proves_savings(self) -> None:
        # Все кандидаты проваливают чекеры -> рекомендации нет
        optimizer = SavingsOptimizer(client_factory=lambda config: FailingClient())

        result = optimizer.optimize(
            goal=self.goal, baseline=BASELINE, candidates=CANDIDATES
        )

        self.assertIsNone(result.best)
        self.assertIsNone(result.recommendation)
        self.assertEqual(result.finalists, ())

    def test_broken_endpoint_eliminated_without_crashing(self) -> None:
        # Недоступный эндпоинт отбраковывается с причиной, прогон не падает
        optimizer = SavingsOptimizer(client_factory=_factory_with_broken_endpoint)
        candidates = CANDIDATES + [
            ModelSpec(model_name="broken-endpoint", tier="economy",
                      input_token_usd_per_m=0.01, output_token_usd_per_m=0.01),
        ]

        result = optimizer.optimize(
            goal=self.goal, baseline=BASELINE, candidates=candidates
        )

        broken = [ev for ev in result.evaluations if ev.model_name == "broken-endpoint"]
        self.assertTrue(broken)
        self.assertTrue(broken[0].eliminated)
        self.assertIn("endpoint error", broken[0].reason)

        # Остальные кандидаты продолжают борьбу
        self.assertEqual(result.best, "economy-model")
        self.assertNotIn("broken-endpoint", result.finalists)

    def test_screening_keeps_indeterminate_candidate(self) -> None:
        # A2: скрининг на подвыборке отбраковывает только явно плохих
        # (точечная оценка ниже порога И верхняя граница CI тоже ниже).
        # Кандидат 1/2 на подвыборке: точечная 0.5 < 0.9, но CI upper
        # ~0.905 > 0.9 — «неопределённый», должен дожить до финала.
        # По старому правилу (точечная оценка) он погиб бы на скрининге.
        big_dataset = tuple(
            {"label": f"case-{i}", "prompt": f"Question {i}?",
             "expect_contains": f"answer-{i}"}
            for i in range(10)
        )
        goal = OptimizationGoal(
            dataset=big_dataset,
            quality_floor=0.9,
            screening_fraction=0.2,  # подвыборка из 2 элементов: case-0, case-5
        )

        class FlakyOnFirstItem:
            """Роняет только case-0 (входит в подвыборку скрининга)."""

            def complete(self, prompt: str, expect=None) -> CompletionResult:
                if prompt == "Question 0?":
                    text = "no idea"
                else:
                    text = f"surely {expect}"
                return CompletionResult(text=text, input_tokens=5,
                                        output_tokens=5, latency_sec=0.001)

        optimizer = SavingsOptimizer(client_factory=lambda config: FlakyOnFirstItem())
        candidates = [
            ModelSpec(model_name="flaky-model", tier="economy",
                      input_token_usd_per_m=0.1, output_token_usd_per_m=0.4),
        ]

        result = optimizer.optimize(goal=goal, baseline=BASELINE, candidates=candidates)

        screening = [
            ev for ev in result.evaluations
            if ev.model_name == "flaky-model" and ev.stage == "screening"
        ]
        self.assertEqual(len(screening), 1)
        self.assertAlmostEqual(screening[0].pass_rate, 0.5)
        self.assertFalse(screening[0].eliminated)
        self.assertIn("flaky-model", result.finalists)

    def test_multiplicity_correction_reported_for_family(self) -> None:
        # A3: при >=2 финалистах применяется Холм–Бонферрони и результат
        # прозрачно публикуется в отчёте.
        result = self.optimizer.optimize(
            goal=self.goal, baseline=BASELINE, candidates=CANDIDATES
        )

        correction = result.multiplicity_correction
        self.assertIsNotNone(correction)
        self.assertEqual(correction["method"], "holm-bonferroni")
        self.assertEqual(correction["family_size"], 2)
        self.assertAlmostEqual(correction["alpha"], 0.05)
        # Оба кандидата идентичны базовой по качеству (b=c=0, p=1.0):
        # значимой деградации нет — оба подтверждены.
        self.assertEqual(sorted(correction["confirmed"]),
                         ["economy-model", "mid-model"])
        for name in ("economy-model", "mid-model"):
            entry = correction["per_finalist"][name]
            self.assertAlmostEqual(entry["mcnemar_p"], 1.0)
            self.assertFalse(entry["reject_symmetry"])
            self.assertFalse(entry["degradation_direction"])

        self.assertIn("multiplicity_correction", result.to_dict())

    def test_multiplicity_correction_none_for_single_finalist(self) -> None:
        # A3: один финалист — семейства нет, поправка не применяется.
        result = self.optimizer.optimize(
            goal=self.goal, baseline=BASELINE, candidates=CANDIDATES[:1]
        )

        self.assertIsNone(result.multiplicity_correction)

    def test_dataset_without_checker_rejected(self) -> None:
        # E6: датасет с элементом без чекера не допускается к оптимизации.
        bad_dataset = (
            {"label": "ok", "prompt": "2+2?", "expect_contains": "4"},
            {"label": "no-checker", "prompt": "anything?"},
        )
        goal = OptimizationGoal(dataset=bad_dataset)

        with self.assertRaises(ValueError):
            self.optimizer.optimize(goal=goal, baseline=BASELINE, candidates=CANDIDATES)


if __name__ == "__main__":
    unittest.main()
