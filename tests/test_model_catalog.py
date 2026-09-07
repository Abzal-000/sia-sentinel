from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sia.model_catalog import ModelCatalog, ModelSpec


def _spec(name: str, **kwargs) -> ModelSpec:
    defaults = {
        "input_token_usd_per_m": 0.1,
        "output_token_usd_per_m": 0.4,
    }
    defaults.update(kwargs)
    return ModelSpec(model_name=name, **defaults)


class ModelSpecTestCase(unittest.TestCase):
    def test_blended_price_weights(self) -> None:
        spec = _spec("m", input_token_usd_per_m=1.0, output_token_usd_per_m=5.0)

        self.assertAlmostEqual(spec.blended_usd_per_m, 0.75 * 1.0 + 0.25 * 5.0)

    def test_unknown_tier_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _spec("m", tier="ultra")

    def test_negative_pricing_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _spec("m", input_token_usd_per_m=-1.0)

    def test_roundtrip_to_dict(self) -> None:
        spec = _spec("m", tier="economy", tags=("chat",), context_window=8192)

        restored = ModelSpec.from_dict(spec.to_dict())

        self.assertEqual(restored, spec)


class ModelCatalogTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = ModelCatalog([
            _spec("premium-a", tier="premium", tags=("chat", "reasoning"),
                  input_token_usd_per_m=3.0, output_token_usd_per_m=15.0),
            _spec("mid-b", tier="mid", tags=("chat",),
                  input_token_usd_per_m=0.6, output_token_usd_per_m=1.8),
            _spec("economy-c", tier="economy", tags=("chat",),
                  input_token_usd_per_m=0.1, output_token_usd_per_m=0.4),
        ])

    def test_duplicate_model_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.add(_spec("mid-b"))

    def test_get_and_len(self) -> None:
        self.assertEqual(len(self.catalog), 3)
        self.assertEqual(self.catalog.get("mid-b").tier, "mid")
        self.assertIsNone(self.catalog.get("missing"))

    def test_filter_by_tier(self) -> None:
        result = self.catalog.filter(tiers=("economy",))

        self.assertEqual([s.model_name for s in result], ["economy-c"])

    def test_filter_by_tags_requires_all(self) -> None:
        result = self.catalog.filter(tags=("chat", "reasoning"))

        self.assertEqual([s.model_name for s in result], ["premium-a"])

    def test_filter_exclude(self) -> None:
        result = self.catalog.filter(exclude=("premium-a",))

        self.assertEqual({s.model_name for s in result}, {"mid-b", "economy-c"})

    def test_cheapest_first(self) -> None:
        ordered = self.catalog.cheapest_first()

        self.assertEqual(
            [s.model_name for s in ordered],
            ["economy-c", "mid-b", "premium-a"],
        )

    def test_from_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_text(
                json.dumps({"models": [self.catalog.get("mid-b").to_dict()]}),
                encoding="utf-8",
            )

            loaded = ModelCatalog.from_json(path)

        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded.get("mid-b").tier, "mid")

    def test_from_json_empty_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_text(json.dumps({"models": []}), encoding="utf-8")

            with self.assertRaises(ValueError):
                ModelCatalog.from_json(path)

    def test_seed_catalog_loads(self) -> None:
        """Сид-каталог проекта после курации 2026-08-26 обязан отказывать.

        Доступ к NIM потерян АККАУКТНО (404 'Not found for account' на
        каждую функцию с действующим ключом; 22 августа всё было живо),
        все три llama-эндпоинта удалены. Пустой каталог НЕ загружается
        молча — from_json бросает ValueError (fail loudly), поэтому
        мёртвый провайдер не может тихо участвовать в отборе кандидатов.
        Живой преемник: flows/groq_priced_catalog.json.
        """
        with self.assertRaises(ValueError):
            ModelCatalog.from_json(
                Path(__file__).resolve().parent.parent / "flows" / "model_catalog.json"
            )

        raw = json.loads(
            (Path(__file__).resolve().parent.parent / "flows" / "model_catalog.json")
            .read_text(encoding="utf-8")
        )
        # Удалённые мёртвые эндпоинты не имеют права вернуться молча
        for model in (
            "meta/llama-3.3-70b-instruct",
            "meta/llama-3.1-70b-instruct",
            "meta/llama-3.1-8b-instruct",
        ):
            self.assertNotIn(model, [m["model_name"] for m in raw["models"]])

        groq = ModelCatalog.from_json(
            Path(__file__).resolve().parent.parent / "flows" / "groq_priced_catalog.json"
        )
        self.assertGreaterEqual(len(groq), 2)
        for model in ("openai/gpt-oss-120b", "openai/gpt-oss-20b"):
            self.assertIsNotNone(groq.get(model), model)


if __name__ == "__main__":
    unittest.main()


class SimulatedReliabilityThreadingTestCase(unittest.TestCase):
    """E6-проводка: simulated_reliability кандидата доезжает до эндпоинта.

    Дыра найдена полноценным демо: поле передавалось в flow, но ModelSpec
    его не имел — молча съедалось, simulated-скрининг автопилота не мог
    различить качество кандидатов и рекомендовал просто самый дешёвый.
    """

    def test_spec_threads_reliability_into_endpoint(self) -> None:
        from sia.optimizer import spec_to_endpoint

        spec = ModelSpec(
            model_name="nano-3b",
            input_token_usd_per_m=0.05,
            output_token_usd_per_m=0.20,
            simulated_reliability=0.55,
        )
        self.assertEqual(spec_to_endpoint(spec).simulated_reliability, 0.55)

    def test_spec_without_reliability_keeps_none(self) -> None:
        from sia.optimizer import spec_to_endpoint

        spec = ModelSpec(model_name="x", input_token_usd_per_m=1, output_token_usd_per_m=1)
        self.assertIsNone(spec_to_endpoint(spec).simulated_reliability)

    def test_reliability_out_of_range_refused(self) -> None:
        with self.assertRaises(ValueError):
            ModelSpec(
                model_name="x", input_token_usd_per_m=1,
                output_token_usd_per_m=1, simulated_reliability=1.5,
            )

    def test_roundtrip_preserves_reliability(self) -> None:
        spec = ModelSpec(
            model_name="x", input_token_usd_per_m=1,
            output_token_usd_per_m=1, simulated_reliability=0.7,
        )
        restored = ModelSpec.from_dict(spec.to_dict())
        self.assertEqual(restored.simulated_reliability, 0.7)


class UnknownKeysRefusedTestCase(unittest.TestCase):
    """Луд-отказ на посторонних ключах каталога: опечатка = ошибка ввода,
    не молчаливое съедание (класс ошибок, найденный демо через пропавшее
    simulated_reliability)."""

    def test_unknown_key_refused_loudly(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            ModelSpec.from_dict({
                "model_name": "x", "input_token_usd_per_m": 1,
                "output_token_usd_per_m": 1, "simulated_reliablity": 0.5,  # опечатка
            })
        self.assertIn("simulated_reliablity", str(ctx.exception))

    def test_all_known_keys_accepted(self) -> None:
        spec = ModelSpec.from_dict({
            "model_name": "x", "input_token_usd_per_m": 1,
            "output_token_usd_per_m": 1, "provider": "p", "base_url": None,
            "api_key_env": "K", "tier": "mid", "context_window": 8192,
            "tags": ["a"], "prices_as_of": "2026-09-06",
            "catalog_version": "r1", "simulated_reliability": 0.5,
        })
        self.assertEqual(spec.simulated_reliability, 0.5)


class ProfileThreadingTestCase(unittest.TestCase):
    """profile кандидата доезжает до эндпоинта (раньше молча съедался
    в пользу тирано-выведенного)."""

    def test_explicit_profile_wins_over_tier(self) -> None:
        from sia.optimizer import spec_to_endpoint

        spec = ModelSpec(
            model_name="small", input_token_usd_per_m=0.1,
            output_token_usd_per_m=0.4, tier="premium",
            profile="concise",  # не то, что вывел бы premium-тир
        )
        self.assertEqual(spec_to_endpoint(spec).profile, "concise")

    def test_profile_none_falls_back_to_tier(self) -> None:
        from sia.optimizer import spec_to_endpoint

        spec = ModelSpec(
            model_name="small", input_token_usd_per_m=0.1,
            output_token_usd_per_m=0.4, tier="premium",
        )
        self.assertEqual(spec_to_endpoint(spec).profile, "verbose")

    def test_unknown_profile_refused(self) -> None:
        from sia.optimizer import spec_to_endpoint

        spec = ModelSpec(
            model_name="x", input_token_usd_per_m=1,
            output_token_usd_per_m=1, profile="chatty",
        )
        with self.assertRaises(ValueError):
            spec_to_endpoint(spec)
