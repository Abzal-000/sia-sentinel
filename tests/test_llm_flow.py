from __future__ import annotations

import unittest
from pathlib import Path

from sia.cost_model import CostModel, PricingConfig
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

    def test_serving_fingerprint_limits_and_provenance_published(self) -> None:
        """П.3/4/5 рецензии: что реально отвечало, кто выбрал кандидата,
        R и n как объявленные пределы рядом с MDD."""
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
        as_dict = report.to_dict()

        # П.3: симулятор честно называет себя обслужившим бэкендом
        self.assertEqual(
            as_dict["usage_old"]["served_model_names"], ["premium-70b"]
        )
        served_new = as_dict["manifest"]["served_endpoints"]["new"]
        self.assertEqual(served_new["model_names"], ["small-8b"])
        self.assertEqual(served_new["system_fingerprints"], ["simulated"])
        # Покрытие по обоим доказательствам, все 4 вызова (2 элемента
        # × 2 повторения) сообщили и имя, и отпечаток
        served_old = as_dict["manifest"]["served_endpoints"]["old"]
        self.assertEqual(
            served_new["fingerprint_coverage"],
            {"reported": 4, "total": 4},
        )
        self.assertEqual(
            served_old["model_name_coverage"],
            {"reported": 4, "total": 4},
        )
        self.assertEqual(as_dict["usage_old"]["system_fingerprint_calls"], 4)
        self.assertEqual(as_dict["usage_old"]["served_model_name_calls"], 4)

        # П.4: прямой аудит — кандидат объявлен пользователем во флоу
        self.assertEqual(as_dict["manifest"]["candidate_selected_by"], "user")

        # П.5: R и n публикуются рядом с MDD как пределы бюджета
        limits = as_dict["equivalence"]["paired"]["declared_limits"]
        self.assertIn("R=2", limits)
        self.assertIn(f"n={len(DATASET)}", limits)

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


class AnchoredMetricTestCase(unittest.TestCase):
    """Метрика маяка expect_contains/digit-anchored: ANSWER= — последней строкой."""

    def setUp(self) -> None:
        self.auditor = LLMFlowAuditor(
            client_factory=lambda config: SimulatedLLMClient(config)
        )
        self.cost_model = CostModel(PricingConfig())
        self.dataset = [
            {"prompt": f"Compute {i}+{i}?", "expect_contains": f"ANSWER={2 * i}"}
            for i in range(1, 7)
        ]
        self.config = LLMEndpointConfig(model_name="m", profile="verbose", seed=3)

    def test_answer_mid_text_does_not_pass(self) -> None:
        from sia.llm_flow import _expect_met

        # Упоминание ANSWER= в рассуждениях посреди текста не засчитывается
        self.assertFalse(_expect_met(
            "ANSWER=480", "Hmm, let me think... not ANSWER=480 yet.\nStill thinking"
        ))
        # Последняя непустая строка, равная ожиданию, — засчитывается
        self.assertTrue(_expect_met("ANSWER=480", "reasoning...\nANSWER=480"))
        # Обычная подстрока работает как раньше; без чекера — проход
        self.assertTrue(_expect_met("Paris", "The capital is Paris"))
        self.assertTrue(_expect_met(None, "anything"))

    def test_simulated_client_anchors_correct_answers(self) -> None:
        from sia.llm_flow import _expect_met

        client = SimulatedLLMClient(
            LLMEndpointConfig(model_name="m", seed=5, simulated_reliability=1.0)
        )
        result = client.complete("Compute 240+240?", expect="ANSWER=480")
        self.assertTrue(_expect_met("ANSWER=480", result.text))

    def test_preregistration_declares_anchored_metric(self) -> None:
        commitment = LLMFlowAuditor.preregistration_commitment(
            self.dataset, self.config, self.config,
            delta=0.05, confidence=0.95, repetitions=1,
        )
        self.assertEqual(commitment["metric"], "expect_contains/digit-anchored")


class LiveClientRetryTestCase(unittest.TestCase):
    """Пункт 1 плана маяка: backoff-повторы SDK вместо глобального троттла.

    SDK сам повторяет 408/409/429/5xx с экспоненциальным backoff и уважает
    Retry-After; max_retries=8 даёт пробе на общем бесплатном пуле запас
    против 429. Худший случай зависшего вызова: timeout × (retries+1) ≈ 540 c.
    """

    def _client(self, **kwargs):
        from sia.llm_flow import LLMEndpointConfig, OpenAICompatibleClient

        config = LLMEndpointConfig(
            model_name="test-model",
            base_url="https://example.com/v1",
            api_key="test-key",
        )
        return OpenAICompatibleClient(config, **kwargs)

    def test_default_max_retries_is_eight(self) -> None:
        client = self._client()

        self.assertEqual(client._client.max_retries, 8)
        self.assertEqual(client._client.timeout, 60.0)

    def test_explicit_retry_and_timeout_propagate(self) -> None:
        client = self._client(request_timeout=30.0, max_retries=3)

        self.assertEqual(client._client.max_retries, 3)
        self.assertEqual(client._client.timeout, 30.0)


class CheckpointResumeTestCase(unittest.TestCase):
    """Чекпойнт живых прогонов: краш теряет максимум текущий вызов."""

    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.auditor = LLMFlowAuditor(
            client_factory=lambda config: SimulatedLLMClient(config)
        )
        self.cost_model = CostModel(PricingConfig())
        self.dataset = [
            {"prompt": f"Question {i}?", "expect_contains": str(i % 10)}
            for i in range(12)
        ]
        self.config = LLMEndpointConfig(model_name="m", profile="verbose", seed=7)
        self.checkpoint = Path(self._tmp.name) / "probe" / "llm-audit-new.jsonl"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _reference(self) -> tuple:
        result = self.auditor.evaluate_config(
            SimulatedLLMClient(self.config), self.dataset, 2, self.cost_model
        )
        return result

    def _flaky(self, fail_on_call: int):
        inner = SimulatedLLMClient(self.config)
        calls = {"n": 0}

        class Flaky:
            config = inner.config

            def complete(self, prompt, expect=None):
                calls["n"] += 1

                if calls["n"] == fail_on_call:
                    raise RuntimeError("timeout after retries")
                return inner.complete(prompt, expect=expect)

        return Flaky()

    def test_header_matches_preregistration_commitment(self) -> None:
        import json

        self.auditor.evaluate_config(
            SimulatedLLMClient(self.config), self.dataset, 2, self.cost_model,
            checkpoint=self.checkpoint,
        )
        header = json.loads(self.checkpoint.read_text(encoding="utf-8").splitlines()[0])

        from sia.llm_flow import _CheckpointJournal

        self.assertEqual(header["protocol"], _CheckpointJournal.PROTOCOL)
        self.assertEqual(header["checker"], _CheckpointJournal.CHECKER_ID)
        self.assertEqual(header["repetitions"], 2)
        commitment = LLMFlowAuditor.preregistration_commitment(
            self.dataset, self.config, self.config, delta=0.05
        )
        self.assertEqual(
            header["dataset_sha256"], commitment["dataset_sha256"]
        )
        self.assertEqual(header["endpoint"], self.config.public_dict())

    def test_crash_then_resume_equals_reference(self) -> None:
        import json

        reference = self._reference()

        # Первый заход падает на 9-м вызове (после 8 записанных)
        with self.assertRaises(RuntimeError):
            self.auditor.evaluate_config(
                self._flaky(fail_on_call=9), self.dataset, 2, self.cost_model,
                checkpoint=self.checkpoint,
            )

        recorded = len(self.checkpoint.read_text(encoding="utf-8").splitlines()) - 1
        self.assertEqual(recorded, 8)

        # Возобновление тем же клиентом и путём — доигрывает без повторов
        resumed = self.auditor.evaluate_config(
            SimulatedLLMClient(self.config), self.dataset, 2, self.cost_model,
            checkpoint=self.checkpoint,
        )

        ref_usage, _, ref_passed, ref_total, ref_passes = reference
        res_usage, _, res_passed, res_total, res_passes = resumed

        # Итоги возобновлённого прогона совпадают с бесаварийным референсом
        self.assertEqual(res_usage.calls, ref_usage.calls)
        self.assertEqual(res_usage.input_tokens, ref_usage.input_tokens)
        self.assertEqual(res_usage.output_tokens, ref_usage.output_tokens)
        self.assertEqual(res_usage.total_cost_usd, ref_usage.total_cost_usd)
        self.assertEqual((res_passed, res_total), (ref_passed, ref_total))
        self.assertEqual(res_passes, ref_passes)

        trials = [
            json.loads(line)
            for line in self.checkpoint.read_text(encoding="utf-8").splitlines()[1:]
        ]
        self.assertEqual(len(trials), 24)  # 12 элементов × 2 повторения
        keys = {(t["item"], t["rep"]) for t in trials}
        self.assertEqual(len(keys), 24)  # ни одного дубликата

        # П.3: отпечатки обслужившего бэкенда едут в журнале — агрегат
        # после возобновления покрывает весь прогон, включая вызовы до краша
        self.assertEqual(res_usage.served_model_names, ("m",))
        self.assertEqual(res_usage.system_fingerprints, ("simulated",))
        self.assertEqual(res_usage.system_fingerprint_calls, 24)

    def test_legacy_protocol_v1_journal_refused(self) -> None:
        """Журналы пробы с префиксным чекером (/1) не доигрываются новым кодом:
        семантика метрики сменилась, а dataset_sha256 её не видит."""
        import json

        self.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        legacy_header = {
            "protocol": "llm-flow-checkpoint/1",
            "dataset_sha256": self.auditor._dataset_hash(self.dataset),
            "endpoint": self.config.public_dict(),
            "repetitions": 2,
        }
        self.checkpoint.write_text(
            json.dumps(legacy_header, sort_keys=True) + "\n", encoding="utf-8"
        )

        with self.assertRaises(ValueError) as ctx:
            self.auditor.evaluate_config(
                SimulatedLLMClient(self.config), self.dataset, 2,
                self.cost_model, checkpoint=self.checkpoint,
            )

        self.assertIn("different dataset or configuration", str(ctx.exception))

    def test_checker_identity_mismatch_refused(self) -> None:
        """Смена семантики чекера ловится сравнением заголовков автоматически."""
        import json


        self.auditor.evaluate_config(
            SimulatedLLMClient(self.config), self.dataset, 2, self.cost_model,
            checkpoint=self.checkpoint,
        )
        lines = self.checkpoint.read_text(encoding="utf-8").splitlines()
        header = json.loads(lines[0])
        header["checker"] = "expect_contains:substring@v1"  # «старый» чекер
        self.checkpoint.write_text(
            "\n".join([json.dumps(header, sort_keys=True)] + lines[1:]) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            self.auditor.evaluate_config(
                SimulatedLLMClient(self.config), self.dataset, 2,
                self.cost_model, checkpoint=self.checkpoint,
            )

    def test_resume_refuses_different_repetitions(self) -> None:
        # Предрегистрация фиксирует R — заголовок журнала обязан нести то
        # же число, иначе доигрывание с другим R прошло бы молча
        self.auditor.evaluate_config(
            SimulatedLLMClient(self.config), self.dataset, 2, self.cost_model,
            checkpoint=self.checkpoint,
        )

        with self.assertRaises(ValueError) as ctx:
            self.auditor.evaluate_config(
                SimulatedLLMClient(self.config), self.dataset, 3,
                self.cost_model, checkpoint=self.checkpoint,
            )

        self.assertIn("different dataset or configuration", str(ctx.exception))

    def test_hidden_pricing_fields_cannot_shift_token_cost(self) -> None:
        """Сторож инварианта возобновления: всё, что влияет на token_cost,
        обязано быть в public_dict() — иначе заголовок чекпойнта не
        фиксирует ценовой базис, и доигрывание молча смешало бы базисы.

        Механика: для каждого поля PricingConfig, ОТСУТСТВУЮЩЕГО в
        public_dict(), мутация этого поля не должна менять token_cost.
        Если завтра добавят плату за запрос и забудут вынести в
        public_dict() — этот тест упадёт.
        """
        import dataclasses

        from sia.cost_model import CostModel

        config = LLMEndpointConfig(model_name="m")
        public_keys = set(config.public_dict())
        volume_in, volume_out = 1_000_000, 500_000
        base_cost = CostModel(
            config.resolve_pricing(PricingConfig())
        ).token_cost(volume_in, volume_out)

        for field in dataclasses.fields(PricingConfig):
            if field.name in public_keys:
                continue  # публично => заголовок чекпойнта его фиксирует

            mutated_defaults = dataclasses.replace(
                PricingConfig(),
                **{field.name: type(123.0)(456.0)},
            )
            shifted_cost = CostModel(
                config.resolve_pricing(mutated_defaults)
            ).token_cost(volume_in, volume_out)

            self.assertEqual(
                base_cost, shifted_cost,
                f"Поле PricingConfig.{field.name} отсутствует в "
                "LLMEndpointConfig.public_dict(), но влияет на token_cost: "
                "заголовок чекпойнта не зафиксирует его, и возобновление "
                "молча смешает ценовые базисы. Добавьте поле в public_dict().",
            )

    def test_resume_refuses_foreign_dataset_or_config(self) -> None:
        self.auditor.evaluate_config(
            SimulatedLLMClient(self.config), self.dataset, 2, self.cost_model,
            checkpoint=self.checkpoint,
        )

        other_dataset = [{"prompt": "Other?", "expect_contains": "x"}]
        other_config = LLMEndpointConfig(model_name="m", seed=99)  # другой seed -> другой public_dict

        for bad_dataset, bad_config in (
            (other_dataset, self.config),
            (self.dataset, other_config),
        ):
            with self.assertRaises(ValueError) as ctx:
                self.auditor.evaluate_config(
                    SimulatedLLMClient(bad_config), bad_dataset, 2,
                    self.cost_model, checkpoint=self.checkpoint,
                )

            self.assertIn("different dataset or configuration", str(ctx.exception))

    def test_torn_trailing_line_is_dropped_and_rerun(self) -> None:
        self.auditor.evaluate_config(
            SimulatedLLMClient(self.config), self.dataset, 2, self.cost_model,
            checkpoint=self.checkpoint,
        )

        # Крах посреди записи: неполная последняя строка
        with open(self.checkpoint, "a", encoding="utf-8") as handle:
            handle.write('{"item": 11, "rep": 1, "ok": tru')

        result = self.auditor.evaluate_config(
            SimulatedLLMClient(self.config), self.dataset, 2, self.cost_model,
            checkpoint=self.checkpoint,
        )

        reference = self._reference()
        self.assertEqual(result[3], reference[3])  # total_trials как у референса


if __name__ == "__main__":
    unittest.main()
