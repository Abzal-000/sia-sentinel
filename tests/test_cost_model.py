from __future__ import annotations

import unittest

from sia.cost_model import CostModel, PricingConfig, SavingsResult


class PricingConfigTestCase(unittest.TestCase):
    def test_defaults_and_to_dict(self) -> None:
        config = PricingConfig()

        as_dict = config.to_dict()

        self.assertAlmostEqual(as_dict["compute_usd_per_hour"], 2.0)
        self.assertAlmostEqual(as_dict["input_token_usd_per_m"], 0.15)
        self.assertAlmostEqual(as_dict["output_token_usd_per_m"], 0.60)

    def test_custom_pricing(self) -> None:
        config = PricingConfig(compute_usd_per_hour=5.5, input_token_usd_per_m=0.5)
        model = CostModel(config)

        self.assertAlmostEqual(model.compute_cost(3600.0), 5.5)
        self.assertAlmostEqual(model.token_cost(1_000_000, 0), 0.5)


class CostModelTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.model = CostModel(PricingConfig(compute_usd_per_hour=3.6))

    def test_compute_cost(self) -> None:
        # Час работы = 3.6$, секунда = 0.001$
        self.assertAlmostEqual(self.model.compute_cost(3600.0), 3.6)
        self.assertAlmostEqual(self.model.compute_cost(1.0), 0.001)

    def test_compute_cost_invalid_duration(self) -> None:
        self.assertEqual(self.model.compute_cost(-5), 0.0)
        self.assertEqual(self.model.compute_cost(None), 0.0)

    def test_token_cost(self) -> None:
        model = CostModel(
            PricingConfig(input_token_usd_per_m=1.0, output_token_usd_per_m=2.0)
        )

        self.assertAlmostEqual(model.token_cost(1_000_000, 500_000), 2.0)
        self.assertEqual(model.token_cost(0, 0), 0.0)
        self.assertEqual(model.token_cost(-10, -10), 0.0)

    def test_estimate_tokens(self) -> None:
        self.assertEqual(CostModel.estimate_tokens(""), 0)
        self.assertEqual(CostModel.estimate_tokens("abcd"), 1)
        self.assertEqual(CostModel.estimate_tokens("a" * 400), 100)

    def test_compare_savings(self) -> None:
        savings = self.model.compare(0.010, 0.002)

        self.assertIsInstance(savings, SavingsResult)
        self.assertAlmostEqual(savings.savings_usd, 0.008)
        self.assertAlmostEqual(savings.savings_ratio, 0.8)
        self.assertAlmostEqual(savings.savings_per(1000), 8.0)

        as_dict = savings.to_dict()
        self.assertAlmostEqual(as_dict["savings_usd_per_1k_runs"], 8.0)
        self.assertIn("savings_ratio", as_dict)

    def test_compare_zero_old_cost(self) -> None:
        savings = self.model.compare(0.0, 0.005)

        self.assertEqual(savings.savings_ratio, 0.0)
        self.assertAlmostEqual(savings.savings_usd, -0.005)


if __name__ == "__main__":
    unittest.main()
