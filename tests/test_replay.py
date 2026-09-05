"""Б2: replay_tolerance исполняется кодом — тесты сравнения записи и повтора.

Дизайн: сравниваются исходный отчёт (record) и независимый повторный прогон
(replay) на одном флоу. Порог — на ОДНОСТОРОННЕЙ доле «к заявлению»:
честный повторитель дрейфует симметрично (toward и away сравнимы), подлог
толкает в одну сторону. Числа в тестах вычисляются из правила, не из
эфемерных фиксстур, чтобы сломать тест могла только реальная регрессия.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "verifier"))

from sia_verifier.replay import (  # noqa: E402
    ReplayInapplicable,
    compare_replays,
)


def _flow(n: int) -> dict:
    return {
        "kind": "llm_flow",
        "dataset": [
            {"label": f"i{i}", "prompt": f"q{i}", "expect_contains": f"ANSWER={i}"}
            for i in range(n)
        ],
    }


def _report(
    flow: dict,
    failed_old: list[str] | None = None,
    failed_new: list[str] | None = None,
    repetitions: int = 1,
    replay_tolerance: float = 0.05,
) -> dict:
    from sia_verifier.rederive import _dataset_hash

    return {
        "name": "test",
        "equivalence": {
            "failed_old": failed_old or [],
            "failed_new": failed_new or [],
        },
        "preregistration": {
            "dataset_sha256": _dataset_hash(flow["dataset"]),
            "replay_tolerance": replay_tolerance,
            "repetitions": repetitions,
        },
    }


class ReplayDirectionTestCase(unittest.TestCase):
    """Классификация четырёх направлений сдвига (по стороне и по знаку)."""

    def test_identical_replay_is_perfectly_within(self) -> None:
        flow = _flow(100)
        record = _report(flow, failed_old=["i0"], failed_new=["i0", "i1"])
        replay = _report(flow, failed_old=["i0"], failed_new=["i0", "i1"])
        result = compare_replays(record, replay, flow)
        self.assertTrue(result["within_tolerance"])
        self.assertEqual(result["toward_elements"], 0)
        self.assertEqual(result["away_elements"], 0)

    def test_old_pass_to_fail_is_toward(self) -> None:
        # Старая конфигурация В ПОВТОРЕ упала там, где записала успех —
        # это сдвиг К заявлению (запись выглядит не строже повтора).
        flow = _flow(100)
        record = _report(flow, failed_old=[], failed_new=[])
        replay = _report(flow, failed_old=["i0"], failed_new=[])
        result = compare_replays(record, replay, flow)
        self.assertEqual(result["side_breakdown"]["old_pass_to_fail"], 1)
        self.assertEqual(result["toward_elements"], 1)
        self.assertTrue(result["within_tolerance"])  # 1/100 = 1% < 5%

    def test_new_fail_to_pass_is_toward(self) -> None:
        flow = _flow(100)
        record = _report(flow, failed_old=[], failed_new=["i0"])
        replay = _report(flow, failed_old=[], failed_new=[])
        result = compare_replays(record, replay, flow)
        self.assertEqual(result["side_breakdown"]["new_fail_to_pass"], 1)
        self.assertEqual(result["toward_elements"], 1)

    def test_new_pass_to_fail_is_away(self) -> None:
        # Новая конфигурация в повторе СТАЛА ХУЖЕ — сдвиг ОТ заявления,
        # должен НЕ расходовать допуск, но его видно в breakdown.
        flow = _flow(100)
        record = _report(flow, failed_old=[], failed_new=[])
        replay = _report(flow, failed_old=[], failed_new=["i0"])
        result = compare_replays(record, replay, flow)
        self.assertEqual(result["side_breakdown"]["new_pass_to_fail"], 1)
        self.assertEqual(result["away_elements"], 1)
        self.assertEqual(result["toward_elements"], 0)
        self.assertTrue(result["within_tolerance"])

    def test_old_fail_to_pass_is_away(self) -> None:
        flow = _flow(100)
        record = _report(flow, failed_old=["i0"], failed_new=[])
        replay = _report(flow, failed_old=[], failed_new=[])
        result = compare_replays(record, replay, flow)
        self.assertEqual(result["side_breakdown"]["old_fail_to_pass"], 1)
        self.assertEqual(result["away_elements"], 1)


class ReplayToleranceTestCase(unittest.TestCase):
    """Ворота: односторонняя доля к заявлению против допуска."""

    def test_forgery_beyond_tolerance_fails(self) -> None:
        # Подлог: в записи новая сторона выглядит хуже, чем в «повторе»,
        # на 6 из 100 элементов — 6% > 5% допуска → REPLAY MISMATCH.
        flow = _flow(100)
        hidden = [f"i{i}" for i in range(6)]
        record = _report(flow, failed_old=[], failed_new=hidden)
        replay = _report(flow, failed_old=[], failed_new=[])
        result = compare_replays(record, replay, flow)
        self.assertEqual(result["toward_elements"], 6)
        self.assertAlmostEqual(result["toward_share"], 0.06)
        self.assertFalse(result["within_tolerance"])

    def test_honest_symmetric_drift_passes(self) -> None:
        # Честный дрейф (измерен на записи №1: 1–4 из 90 на сторону) —
        # расходится в ОБЕ стороны, поэтому в ворота не упирается.
        flow = _flow(100)
        record = _report(flow, failed_old=["i0", "i1"], failed_new=["i2", "i3"])
        replay = _report(flow,
                         failed_old=["i10", "i11"],
                         failed_new=["i12", "i13", "i2"])  # i3 прошла в повторе
        result = compare_replays(record, replay, flow)
        # toward: old i10,i11 (pass→fail +2), new i3 (fail→pass +1) — 3 всего.
        # away:   old i0,i1 (fail→pass +2), new i12,i13 (pass→fail +2) — 4,
        # (i2 провалена в обоих прогонах — не расхождение вообще).
        # 3% < 5% → внутри; симметрия видна в breakdown.
        self.assertTrue(result["within_tolerance"])
        self.assertEqual(result["toward_elements"], 3)
        self.assertEqual(result["away_elements"], 4)

    def test_tolerance_edge_inclusive(self) -> None:
        # Ровно на границе (5 из 100 = 5%) — ВНУТРИ (неравенство ≤).
        flow = _flow(100)
        record = _report(flow, failed_old=[],
                         failed_new=[f"i{i}" for i in range(5)])
        replay = _report(flow, failed_old=[], failed_new=[])
        result = compare_replays(record, replay, flow)
        self.assertAlmostEqual(result["toward_share"], 0.05)
        self.assertTrue(result["within_tolerance"])

    def test_one_beyond_edge_fails(self) -> None:
        flow = _flow(100)
        record = _report(flow, failed_old=[],
                         failed_new=[f"i{i}" for i in range(6)])
        replay = _report(flow, failed_old=[], failed_new=[])
        self.assertFalse(compare_replays(record, replay, flow)["within_tolerance"])

    def test_custom_tolerance_respected(self) -> None:
        flow = _flow(100)
        record = _report(flow, failed_new=[f"i{i}" for i in range(4)],
                         replay_tolerance=0.03)
        replay = _report(flow, failed_new=[])
        result = compare_replays(record, replay, flow)
        self.assertEqual(result["tolerance"], 0.03)
        self.assertFalse(result["within_tolerance"])  # 4% > 3%


class ReplayInapplicableTestCase(unittest.TestCase):
    """Отказ = «неприменимо», а не «не прошло» (статус ≠ вердикт)."""

    def test_different_dataset_refused(self) -> None:
        flow = _flow(10)
        record = _report(flow)
        # отчёт от ДРУГОГО датасета
        other_flow = _flow(5)
        replay = _report(other_flow)
        with self.assertRaises(ReplayInapplicable):
            compare_replays(record, replay, flow)

    def test_different_repetitions_refused(self) -> None:
        flow = _flow(10)
        record = _report(flow, repetitions=1)
        replay = _report(flow, repetitions=2)
        with self.assertRaises(ReplayInapplicable) as ctx:
            compare_replays(record, replay, flow)
        self.assertIn("repetitions", str(ctx.exception))

    def test_unlabeled_dataset_refused(self) -> None:
        flow = {"kind": "llm_flow",
                "dataset": [{"prompt": "q", "expect_contains": "ANSWER=1"}]}
        record = _report(flow)
        with self.assertRaises(ReplayInapplicable):
            compare_replays(record, _report(flow), flow)


if __name__ == "__main__":
    unittest.main()
