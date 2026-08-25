"""Блокеры маяка (мини-аудит 2026-08-22): размер датасета и датировка цен."""
from __future__ import annotations

import unittest

from sia.flow_runner import (
    MAX_DATASET_ITEMS,
    build_preregistration_commitment,
    run_flow_audit,
)


def _item(i: int) -> dict:
    return {"prompt": f"Question number {i}?", "expect_contains": str(i)}


def _flow(n: int, **extra: object) -> dict:
    return {
        "kind": "llm_flow",
        "name": "beacon-sized-flow",
        "dataset": [_item(i) for i in range(n)],
        "old": {
            "model_name": "premium",
            "profile": "verbose",
            "input_token_usd_per_m": 3.0,
            "output_token_usd_per_m": 15.0,
            "prices_as_of": "2026-08-22",
            "catalog_version": "2026.08",
        },
        "new": {
            "model_name": "small",
            "profile": "concise",
            "input_token_usd_per_m": 0.1,
            "output_token_usd_per_m": 0.4,
            "prices_as_of": "2026-08-22",
            "catalog_version": "2026.08",
        },
        "repetitions": 1,
        "anchor_declaration": "external-anchor",
        **extra,
    }


class DatasetLimitTestCase(unittest.TestCase):
    """Лимит датасета не должен быть статистическим ограничением.

    δ=5 п.п. при 10% дискордантности требует n≈314; при старом лимите
    200 публикуемый MDD (6.26 п.п.) превышал заявляемую δ — протокол не мог
    обосновать круглое пятипроцентное заявление на максимально разрешённом
    датасете, а маяк на 250 задач отвергался и предрегистрацией, и аудитом.
    """

    def test_limit_covers_statistically_sound_beacon(self) -> None:
        self.assertGreaterEqual(MAX_DATASET_ITEMS, 500)

    def test_preregistration_accepts_300_items(self) -> None:
        commitment = build_preregistration_commitment(_flow(300))

        self.assertIn("dataset_sha256", commitment)

    def test_audit_accepts_300_items(self) -> None:
        report = run_flow_audit(_flow(300))

        self.assertEqual(report["equivalence"]["total"], 300)
        self.assertEqual(report["manifest"]["dataset_size"], 300)
        self.assertEqual(report["mode"], "simulated")

    def test_oversized_dataset_still_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            build_preregistration_commitment(_flow(MAX_DATASET_ITEMS + 1))

        self.assertIn("dataset too large", str(ctx.exception))


class DatedPricingTestCase(unittest.TestCase):
    """Манифест аудита обязан нести датировку цен, как и предрегистрация.

    Раньше путь аудита собирал эндпоинты локальным дубликатом без
    prices_as_of/catalog_version — обязательство цены датирует, а манифест
    самого аудита нет: E5 отваливался ровно там, где важнее всего.
    """

    def test_manifest_and_preregistration_carry_dated_pricing(self) -> None:
        report = run_flow_audit(_flow(20))

        manifest = report["manifest"]
        self.assertEqual(manifest["old_endpoint"]["prices_as_of"], "2026-08-22")
        self.assertEqual(manifest["new_endpoint"]["prices_as_of"], "2026-08-22")
        self.assertEqual(manifest["old_endpoint"]["catalog_version"], "2026.08")
        self.assertEqual(manifest["new_endpoint"]["catalog_version"], "2026.08")

        # Обязательство предрегистрации в отчёте датирует те же цены —
        # манифест и обязательство не могут разойтись
        endpoints = report["preregistration"]["endpoints"]
        self.assertEqual(endpoints["old"]["prices_as_of"], "2026-08-22")
        self.assertEqual(endpoints["new"]["prices_as_of"], "2026-08-22")
        self.assertEqual(endpoints["old"]["catalog_version"], "2026.08")


if __name__ == "__main__":
    unittest.main()
