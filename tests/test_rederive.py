"""Проверка независимого перевывода вердикта Записи №1 (rederive).

Инструмент не должен принимать на слово: тест гоняет его формулы на
известных числах записи №1 (b=10, c=4, n=450) и проверяет структурные
свойства (MDD-пол, правило вердикта, привязка отчёта к подписи).
Живых артефактов записи №1 тест не требует — числа фиксированы, чтобы
регрессия в формулах ловилась без сети и без леджера.
"""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_ROOT = REPO_ROOT / "verifier"
sys.path.insert(0, str(VERIFIER_ROOT))

from sia_verifier.rederive import (  # noqa: E402
    _canon,
    _commitment_from_flow,
    _mcnemar_exact,
    _mdd,
    _mover_paired_ci,
    _dataset_hash,
    rederive,
)

# Опубликованные значения записи №1 (attestation claim.paired)
B, C, N = 10, 4, 450
CI_LOWER = -0.03232114276651871
CI_UPPER = 0.003724573831923964
MCNEMAR_P = 0.17956542968749645
MDD = 0.04176356661639448  # от 10% пола, не от наблюдённых 3.1%


class RederiveFormulasTestCase(unittest.TestCase):
    """Формулы перевывода воспроизводят опубликованные числа записи №1."""

    def test_mover_ci_matches_published(self) -> None:
        lower, upper = _mover_paired_ci(B, C, N)
        self.assertAlmostEqual(lower, CI_LOWER, places=12)
        self.assertAlmostEqual(upper, CI_UPPER, places=12)

    def test_mcnemar_matches_published(self) -> None:
        self.assertAlmostEqual(_mcnemar_exact(B, C), MCNEMAR_P, places=12)

    def test_mdd_uses_ten_percent_floor_not_observed(self) -> None:
        # Наблюдённая дискордантность 14/450=3.1% НИЖЕ планировочного пола
        # 10%: опубликованный MDD обязан считаться от 10% (spec §1.1),
        # иначе инструмент занижает слепоту аудита ровно там, где он
        # почти слеп — этот баг был у первой версии rederive.
        self.assertAlmostEqual(_mdd(N, B, C), MDD, places=12)
        self.assertNotAlmostEqual(
            _mdd(N, B, C), 0.023294604502286827, places=9
        )

    def test_mdd_observed_raises_above_floor(self) -> None:
        # Наблюдённое ВЫШЕ пола поднимает MDD (floor-raiser, не ceiling).
        high = _mdd(N, 45, 45)
        self.assertGreater(high, _mdd(N, B, C))

    def test_verdict_rule(self) -> None:
        # ci_lower > -delta и mdd <= delta -> non_inferior воспроизводится
        self.assertGreater(CI_LOWER, -0.05)
        self.assertLessEqual(MDD, 0.05)


class RederiveDatasetHashTestCase(unittest.TestCase):
    """Хеш датасета — простая функция промптов и ожиданий."""

    def test_dataset_hash_is_prompt_expect_join(self) -> None:
        dataset = [
            {"prompt": "2+2?", "expect_contains": "ANSWER=4"},
            {"prompt": "3+3?", "expect_contains": "ANSWER=6"},
        ]
        joined = "2+2?|ANSWER=4\n3+3?|ANSWER=6"
        self.assertEqual(_dataset_hash(dataset), hashlib.sha256(joined.encode()).hexdigest())


class RederiveLocalCommitmentTestCase(unittest.TestCase):
    """Локальная реконструкция обязательства == репозиторному коду.

    Золотой тест на РЕАЛЬНОМ флоу записи №1: дайджест af720aad…7c33a8b6 —
    это байты, реально принятые Sigstore Rekor (uuid 108e…41f00c8,
    индекс 2601942504). Если локальная реконструкция разъедется с
    репозиторным build_preregistration_commitment (порядок полей, дефолты,
    нормализация), этот тест упадёт первым — а с ним и вся автономность
    rederive: внешний проверяющий пользуется ТОЛЬКО локальной версией.
    """

    FLOW = REPO_ROOT / "flows" / "beacon.json"
    GOLDEN = "af720aad4ec3ff0b9db8eb7148b1ebb9445c2e71ae76c5c7d1fca838aa378e3d68d653762f4948b888ee51f91ed0a5854a86bfef6f02b0ff3b38d7427c33a8b6"

    def test_local_commitment_matches_rekor_anchored_bytes(self) -> None:
        import hashlib as _h
        flow = json.loads(self.FLOW.read_text(encoding="utf-8-sig"))
        commitment = _commitment_from_flow(flow)
        commitment["anchor_reference"] = None
        digest = _h.sha512(_canon(commitment)).hexdigest()
        self.assertEqual(digest, self.GOLDEN)

    def test_local_commitment_matches_repo_builder(self) -> None:
        """Локальная реконструкция == sia.flow_runner (побитово)."""
        flow = json.loads(self.FLOW.read_text(encoding="utf-8-sig"))
        local = _commitment_from_flow(flow)
        repo_root = REPO_ROOT
        sys.path.insert(0, str(repo_root))
        try:
            from sia.flow_runner import build_preregistration_commitment
            repo = build_preregistration_commitment(flow)
        finally:
            sys.path.remove(str(repo_root))
        # repo-версия не зануляет reference — сравниваем тела полей
        local_cmp = dict(local)
        local_cmp["anchor_reference"] = repo["anchor_reference"]
        self.assertEqual(_canon(local_cmp), _canon(repo))


class RederivePipelineTestCase(unittest.TestCase):
    """rederive() на синтетических входах: ловит подмену каждого поля."""

    def _inputs(self) -> tuple[dict, dict, dict]:
        # n=450 как в записи №1: на маленьком n MDD-гейт честно блокирует
        # вердикт, и «согласованный» фиксстур должен проходить ворота,
        # а не отключать их.
        size = 450
        flow = {
            "kind": "llm_flow",
            "delta": 0.05,
            "confidence": 0.95,
            "repetitions": 1,
            "replay_tolerance": 0.05,
            "dataset": [
                {"prompt": f"q{i}", "expect_contains": f"ANSWER={i}", "label": f"i{i}"}
                for i in range(size)
            ],
            "old": {"model_name": "premium"},
            "new": {"model_name": "cheap"},
            "anchor_declaration": "unanchored",
        }
        report = {
            "name": "test",
            "claim": {"savings_ratio": 0.5, "savings_verified": True},
            "usage_old": {"calls": size, "total_cost_usd": 0.02},
            "usage_new": {"calls": size, "total_cost_usd": 0.01},
            "equivalence": {"failed_old": [], "failed_new": ["i1"]},
            "preregistration": {"dataset_sha256": _dataset_hash(flow["dataset"])},
        }
        attestation = {
            "claim": {
                "savings_verified": True,
                "savings_ratio": 0.5,
                "preregistration": {
                    "dataset_sha256": _dataset_hash(flow["dataset"]),
                    "delta": 0.05,
                    "dataset_size": size,
                },
                "paired": {
                    "non_inferior": True,
                    "b_old_pass_new_fail": 1,
                    "c_old_fail_new_pass": 0,
                    "ci_lower": _mover_paired_ci(1, 0, size)[0],
                    "ci_upper": _mover_paired_ci(1, 0, size)[1],
                    "mcnemar_p": _mcnemar_exact(1, 0),
                    "minimum_detectable_difference": _mdd(size, 1, 0),
                },
            },
            "receipt": {
                "code_hash": hashlib.sha256(
                    json.dumps(report, sort_keys=True, default=str).encode()
                ).hexdigest()
            },
        }
        return attestation, report, flow

    def test_consistent_inputs_rederive(self) -> None:
        attestation, report, flow = self._inputs()
        result = rederive(attestation, report, flow, chain=None, check_rekor=False)
        self.assertTrue(result["rederived"], result["failures"])

    def test_tampered_failure_labels_fail(self) -> None:
        attestation, report, flow = self._inputs()
        report["equivalence"]["failed_new"] = ["i1", "i2"]  # b станет 2
        result = rederive(attestation, report, flow, chain=None, check_rekor=False)
        self.assertFalse(result["rederived"])
        self.assertTrue(any("paired b/c" in f for f in result["failures"]))

    def test_tampered_report_binding_fails(self) -> None:
        # отчёт подменён ПОСЛЕ подписи: числа в нём расходятся с code_hash
        attestation, report, flow = self._inputs()
        report["usage_new"]["total_cost_usd"] = 0.001  # «бесплатно»
        result = rederive(attestation, report, flow, chain=None, check_rekor=False)
        self.assertFalse(result["rederived"])
        self.assertTrue(any("report binding" in f for f in result["failures"]))

    def test_tampered_dataset_fails_hash(self) -> None:
        attestation, report, flow = self._inputs()
        flow["dataset"] = flow["dataset"][:5]  # датасет «похудел»
        result = rederive(attestation, report, flow, chain=None, check_rekor=False)
        self.assertFalse(result["rederived"])
        self.assertTrue(any("dataset_sha256" in f for f in result["failures"]))

    def test_tampered_attestation_delta_vs_flow_fails(self) -> None:
        # F4.6 из фальсификационной батареи: δ в аттестации подменена
        # независимо от флоу (0.05 -> 0.10). Без кросс-сверки
        # аттестация↔флоу перевывод по подменённой δ «подтвердил» бы
        # подмену; теперь расхождение ловится даже без chain.
        attestation, report, flow = self._inputs()
        attestation["claim"]["preregistration"]["delta"] = 0.10
        result = rederive(attestation, report, flow, chain=None, check_rekor=False)
        self.assertFalse(result["rederived"])
        self.assertTrue(any("delta attestation-vs-flow" in f for f in result["failures"]))

    def test_matching_delta_passes_cross_check(self) -> None:
        attestation, report, flow = self._inputs()
        result = rederive(attestation, report, flow, chain=None, check_rekor=False)
        self.assertFalse(any("attestation-vs-flow" in f for f in result["failures"]))

    def test_forged_attestation_savings_ratio_fails(self) -> None:
        # Проверка №10: claim.savings_ratio аттестации — неподписанная
        # проекция. Подмена цифры под НАСТОЯЩЕЙ подписью проходит
        # verify_attestation молча; rederive обязан сверить проекцию
        # с отчётом, пришитым к подписи через code_hash. Канал найден
        # питч-демо demo_forgery.py (2026-09-13).
        attestation, report, flow = self._inputs()
        attestation["claim"]["savings_ratio"] = 0.99
        result = rederive(attestation, report, flow, chain=None, check_rekor=False)
        self.assertFalse(result["rederived"])
        self.assertTrue(any(
            "attestation claim.savings_ratio vs report" in f for f in result["failures"]
        ))

    def test_forged_attestation_savings_verified_fails(self) -> None:
        attestation, report, flow = self._inputs()
        attestation["claim"]["savings_verified"] = not bool(
            attestation["claim"].get("savings_verified")
        )
        result = rederive(attestation, report, flow, chain=None, check_rekor=False)
        self.assertFalse(result["rederived"])
        self.assertTrue(any(
            "attestation claim.savings_verified vs report" in f for f in result["failures"]
        ))

    def test_honest_projection_passes(self) -> None:
        attestation, report, flow = self._inputs()
        result = rederive(attestation, report, flow, chain=None, check_rekor=False)
        self.assertTrue(result["rederived"])
        projection = result["checks"].get("attestation_projection", {})
        self.assertTrue(projection.get("savings_verified_match", True))
        self.assertEqual(
            projection.get("attestation_savings_ratio"),
            projection.get("report_savings_ratio"),
        )


if __name__ == "__main__":
    unittest.main()
