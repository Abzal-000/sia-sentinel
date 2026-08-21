from __future__ import annotations

import unittest

from sia.cost_model import PricingConfig
from sia.llm_flow import (
    CompletionResult,
    LLMEndpointConfig,
    LLMFlowAuditor,
    SimulatedLLMClient,
)

DATASET = [
    {"label": "sum", "prompt": "What is 2+2?", "expect_contains": "4"},
    {"label": "capital", "prompt": "Capital of France?", "expect_contains": "Paris"},
]


class SimulatedLLMClientTestCase(unittest.TestCase):
    def test_deterministic_for_same_seed(self) -> None:
        config = LLMEndpointConfig(model_name="m", profile="verbose", seed=42)

        first = SimulatedLLMClient(config).complete("prompt", expect="42")
        second = SimulatedLLMClient(config).complete("prompt", expect="42")

        self.assertEqual(first.input_tokens, second.input_tokens)
        self.assertEqual(first.output_tokens, second.output_tokens)
        self.assertAlmostEqual(first.latency_sec, second.latency_sec)
        self.assertIn("42", first.text)

    def test_different_seed_changes_usage(self) -> None:
        first = SimulatedLLMClient(LLMEndpointConfig(model_name="m", seed=1)).complete("p")
        second = SimulatedLLMClient(LLMEndpointConfig(model_name="m", seed=2)).complete("p")

        self.assertNotEqual(
            (first.input_tokens, first.output_tokens),
            (second.input_tokens, second.output_tokens),
        )

    def test_unknown_profile_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SimulatedLLMClient(LLMEndpointConfig(model_name="m", profile="turbo"))


class LLMFlowAuditorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.auditor = LLMFlowAuditor(
            defaults=PricingConfig(input_token_usd_per_m=0.15, output_token_usd_per_m=0.60)
        )

    def test_premium_to_small_savings(self) -> None:
        old = LLMEndpointConfig(
            model_name="premium-70b",
            profile="verbose",
            input_token_usd_per_m=3.0,
            output_token_usd_per_m=15.0,
        )
        new = LLMEndpointConfig(
            model_name="small-8b",
            profile="concise",
            input_token_usd_per_m=0.1,
            output_token_usd_per_m=0.4,
        )

        report = self.auditor.audit_flow(DATASET, old, new, repetitions=2)

        self.assertEqual(report.mode, "simulated")
        self.assertEqual(report.equivalence["verdict"], "equivalent")
        self.assertGreater(report.costs.savings_ratio, 0.9)
        self.assertTrue(report.savings_verified)

        as_dict = report.to_dict()
        self.assertEqual(as_dict["protocol"], "proof-of-savings-llm/1")
        self.assertIn("savings_usd_per_1k_calls", as_dict["claim"])

    def test_symmetric_call_accounting(self) -> None:
        old = LLMEndpointConfig(model_name="old", profile="standard")
        new = LLMEndpointConfig(model_name="new", profile="standard")

        report = self.auditor.audit_flow(DATASET, old, new, repetitions=3)

        self.assertEqual(report.usage_old.calls, len(DATASET) * 3)
        self.assertEqual(report.usage_new.calls, len(DATASET) * 3)
        # одинаковые profile -> цена за вызов одного порядка (разброс только
        # от seed-джиттера симулятора)
        self.assertAlmostEqual(
            report.usage_old.unit_cost_usd,
            report.usage_new.unit_cost_usd,
            delta=report.usage_old.unit_cost_usd * 0.3,
        )

    def test_degraded_quality_not_verified(self) -> None:
        class BrokenClient:
            def __init__(self, config):
                self.config = config

            def complete(self, prompt, expect=None):
                return CompletionResult(text="wrong answer", input_tokens=1, output_tokens=1, latency_sec=0.001)

        def factory(config):
            if config.model_name == "broken":
                return BrokenClient(config)
            return SimulatedLLMClient(config)

        auditor = LLMFlowAuditor(client_factory=factory)

        report = auditor.audit_flow(
            DATASET,
            LLMEndpointConfig(model_name="good"),
            LLMEndpointConfig(model_name="broken"),
            repetitions=1,
        )

        self.assertEqual(report.equivalence["verdict"], "degraded")
        self.assertFalse(report.savings_verified)

    def test_manifest_has_no_secrets(self) -> None:
        # Симулированный клиент подставляется явно: манифест тестируем без сети
        auditor = LLMFlowAuditor(client_factory=lambda config: SimulatedLLMClient(config))

        old = LLMEndpointConfig(model_name="old", api_key="sk-secret-old")
        new = LLMEndpointConfig(model_name="new", api_key="sk-secret-new")

        report = auditor.audit_flow(DATASET, old, new)

        manifest_text = str(report.manifest)
        self.assertNotIn("sk-secret", manifest_text)
        self.assertIn("dataset_sha256", report.manifest)
        self.assertEqual(report.manifest["dataset_size"], len(DATASET))

    def test_empty_dataset_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.auditor.audit_flow(
                [],
                LLMEndpointConfig(model_name="old"),
                LLMEndpointConfig(model_name="new"),
            )

    def test_dataset_item_without_checker_rejected(self) -> None:
        # E6: элемент без expect_contains не проверяет ничего — такой
        # датасет не допускается к аудиту.
        dataset = [
            {"label": "ok", "prompt": "2+2?", "expect_contains": "4"},
            {"label": "no-checker", "prompt": "anything?"},
        ]

        with self.assertRaises(ValueError):
            self.auditor.audit_flow(
                dataset,
                LLMEndpointConfig(model_name="old"),
                LLMEndpointConfig(model_name="new"),
            )

    def test_simulated_report_carries_caveat(self) -> None:
        # E6: simulated-режим помечается не только mode, но и явным caveat.
        report = self.auditor.audit_flow(
            DATASET,
            LLMEndpointConfig(model_name="old"),
            LLMEndpointConfig(model_name="new"),
        )

        self.assertEqual(report.mode, "simulated")
        self.assertIsNotNone(report.caveat)
        self.assertIn("Simulated mode", report.caveat)
        self.assertIn("caveat", report.to_dict())

    def test_simulated_reliability_zero_fails_all_checks(self) -> None:
        # E6: симуляция нетавтологична — при надёжности 0.0 ответы не
        # содержат ожидаемую строку, качество «падает», вердикт degraded.
        old = LLMEndpointConfig(model_name="old", simulated_reliability=1.0)
        new = LLMEndpointConfig(model_name="new", simulated_reliability=0.0)

        report = self.auditor.audit_flow(DATASET, old, new, repetitions=1)

        self.assertEqual(report.equivalence["verdict"], "degraded")
        self.assertFalse(report.savings_verified)
        self.assertGreater(report.equivalence["paired"]["b_old_pass_new_fail"], 0)

    def test_simulated_distractor_never_contains_expect(self) -> None:
        # E6: неверный ответ заведомо не содержит ожидаемую строку.
        config = LLMEndpointConfig(model_name="m", simulated_reliability=0.0)
        client = SimulatedLLMClient(config)

        for expect in ("4", "Paris", "answer-1", "a", "0"):
            result = client.complete("some prompt", expect=expect)
            self.assertNotIn(expect, result.text)

    def test_reliability_is_public_manifest_field(self) -> None:
        # E6: допущение о надёжности публично — попадает в манифест.
        report = self.auditor.audit_flow(
            DATASET,
            LLMEndpointConfig(model_name="old", simulated_reliability=0.9),
            LLMEndpointConfig(model_name="new", simulated_reliability=0.8),
        )

        self.assertEqual(
            report.manifest["old_endpoint"]["simulated_reliability"], 0.9
        )
        self.assertEqual(
            report.manifest["new_endpoint"]["simulated_reliability"], 0.8
        )


if __name__ == "__main__":
    unittest.main()
