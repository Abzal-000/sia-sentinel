"""Proof-of-Savings аудитор: проверяемое доказательство экономии.

Склеивает три слоя продукта в один отчёт:
1. Замер производительности обеих конфигураций (воспроизводимо, с таймаутами).
2. Эквивалентность качества на тестовом сьюте с доверительным интервалом.
3. Стоимость в долларах по явным тарифам.

Отчёт сопровождается манифестом воспроизводимости (окружение, хэши кода и
сьюта, seeds, тарифы) — он попадает в подписанную квитанцию Ed25519, и любое
изменение любой части доказательства ломает подпись.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import platform
import sys
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from .cost_model import CostModel, PricingConfig, SavingsResult
from .evaluation_engine import EvaluationEngine
from .models import EquivalenceReport
from .statistics import (
    DEFAULT_ABSOLUTE_QUALITY_FLOOR,
    NonInferiorityResult,
    absolute_quality_met,
    non_inferiority_test,
)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditReport:
    """Итоговый отчёт Proof-of-Savings."""

    manifest: dict[str, Any]
    performance: dict[str, Any]
    equivalence: dict[str, Any]
    costs: Optional[dict[str, Any]]
    quality_score: float
    security_vulnerabilities: int
    overall_efficiency_score: float
    paired: Optional[dict[str, Any]] = None
    # Абсолютный порог качества новой конфигурации. None -> дефолт 0.5.
    quality_floor: Optional[float] = None

    @property
    def _effective_floor(self) -> float:
        return (
            DEFAULT_ABSOLUTE_QUALITY_FLOOR
            if self.quality_floor is None
            else float(self.quality_floor)
        )

    @property
    def new_pass_rate(self) -> float:
        """Наблюдаемая доля тестов сьюта, пройденных новой конфигурацией."""
        return float(self.equivalence.get("pass_rate_new", 0.0))

    @property
    def absolute_quality_ok(self) -> bool:
        """Новая конфигурация сама по себе решает задачи (абсолютный барьер).

        Закрывает дыру «обе версии провалили весь сьют -> нулевая
        дискордантность -> экономия якобы доказана».
        """
        return absolute_quality_met(self.new_pass_rate, self._effective_floor)

    @property
    def relative_non_inferior(self) -> bool:
        """Относительный критерий: новое не хуже старого."""
        if self.paired is not None:
            return bool(self.paired.get("non_inferior")) or (
                self.paired.get("b_old_pass_new_fail", 0) == 0
                and self.paired.get("c_old_fail_new_pass", 0) == 0
            )
        return self.equivalence.get("verdict") == "equivalent"

    @property
    def savings_verified(self) -> bool:
        """Экономия подтверждена: качество сохранено И деньги сэкономлены.

        Требует ОДНОВРЕМЕННО:
        1) относительной неинфериорности (парный тест «новое не хуже старого»);
        2) АБСОЛЮТНОГО качества (новая версия реально проходит тесты сьюта) —
           иначе нулевая дискордантность при полном провале выпустила бы
           квитанцию «экономия доказана» для нерабочей системы;
        3) фактической экономии.
        """
        if not self.costs:
            return False
        return (
            self.relative_non_inferior
            and self.absolute_quality_ok
            and self.costs.get("savings_ratio", 0.0) > 0
        )

    def to_dict(self) -> dict[str, Any]:
        claim: dict[str, Any] = {
            "savings_verified": self.savings_verified,
        }

        if self.costs:
            claim["savings_ratio"] = self.costs.get("savings_ratio")
            claim["savings_usd_per_1k_runs"] = self.costs.get("savings_usd_per_1k_runs")

        claim["equivalence_ci"] = [
            self.equivalence.get("ci_lower"),
            self.equivalence.get("ci_upper"),
        ]
        claim["confidence_level"] = self.equivalence.get("confidence_level")
        claim["absolute_quality"] = {
            "pass_rate_new": self.new_pass_rate,
            "quality_floor": self._effective_floor,
            "absolute_met": self.absolute_quality_ok,
            "relative_non_inferior": self.relative_non_inferior,
        }

        if self.paired is not None:
            claim["delta"] = self.paired.get("delta")
            claim["mcnemar_p"] = self.paired.get("mcnemar_p")
            claim["minimum_detectable_difference"] = self.paired.get(
                "minimum_detectable_difference"
            )
            claim["paired_ci"] = [self.paired.get("ci_lower"), self.paired.get("ci_upper")]

        return {
            "protocol": "proof-of-savings/1",
            "claim": claim,
            "manifest": self.manifest,
            "performance": self.performance,
            "equivalence": self.equivalence,
            "paired": self.paired,
            "costs": self.costs,
            "quality_score": self.quality_score,
            "security_vulnerabilities": self.security_vulnerabilities,
            "overall_efficiency_score": self.overall_efficiency_score,
        }


class ProofOfSavingsAuditor:
    """Проводит аудит пары «старая/новая конфигурация» и готовит доказательство."""

    def __init__(self, evaluation: Optional[EvaluationEngine] = None):
        self.evaluation = evaluation or EvaluationEngine()

    def build_manifest(
        self,
        old_code: str,
        new_code: str,
        test_suite: Sequence[str],
        pricing: Optional[PricingConfig],
        repetitions: int,
        seeds: Sequence[int],
        delta: float,
    ) -> dict[str, Any]:
        return {
            "protocol": "proof-of-savings/1",
            "created": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "environment": {
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "machine": platform.machine(),
            },
            "old_code_sha256": _sha256(old_code),
            "new_code_sha256": _sha256(new_code),
            "test_suite_sha256": _sha256("\n".join(test_suite)),
            "repetitions": repetitions,
            "seeds": [int(seed) for seed in seeds],
            "delta": delta,
            "pricing": pricing.to_dict() if pricing is not None else None,
        }

    def audit(
        self,
        old_code: str,
        new_code: str,
        function_name: str,
        test_suite: Sequence[str],
        args_template: Optional[tuple[Any, ...]] = None,
        pricing: Optional[PricingConfig] = None,
        confidence: float = 0.95,
        repetitions: int = 1,
        seeds: Sequence[int] = (42,),
        delta: float = 0.0,
        quality_floor: Optional[float] = None,
    ) -> AuditReport:
        """Парный аудит: delta — заранее объявленный маркер неинфериорности.

        Для детерминированных тестовых сьютов корректно delta=0 («новое не
        должно уронить ни одного теста, который проходит старое»). Для
        стохастических тестов delta объявляется до прогона.
        """
        normalized_suite = [test.strip() for test in test_suite if test and test.strip()]

        performance = self.evaluation.compare_performance_detailed(
            old_code,
            new_code,
            function_name,
            args_template=args_template,
        )

        equivalence: EquivalenceReport = self.evaluation.check_equivalence_with_confidence(
            old_code,
            new_code,
            normalized_suite,
            confidence=confidence,
            repetitions=repetitions,
        )

        # A1: парная статистика на исходах «тест × версия» — тот же стандарт,
        # что и в llm_flow (Ньюкомб, Макнемар, MDD).
        paired: Optional[NonInferiorityResult] = None
        if equivalence.old_pass and equivalence.new_pass:
            paired = non_inferiority_test(
                equivalence.old_pass,
                equivalence.new_pass,
                delta=delta,
                confidence=equivalence.confidence_level,
            )

        costs: Optional[SavingsResult] = None

        old_time_sec = performance.get("old_time_sec")
        new_time_sec = performance.get("new_time_sec")
        if pricing is not None and old_time_sec is not None and new_time_sec is not None:
            cost_model = CostModel(pricing)
            costs = cost_model.compare(
                cost_model.compute_cost(old_time_sec),
                cost_model.compute_cost(new_time_sec),
            )

        quality_score = self.evaluation.calculate_quality_score(new_code)
        security_vulnerabilities = self.evaluation.count_security_vulnerabilities(new_code)
        overall = self.evaluation.calculate_overall_efficiency_score(
            performance_gain=performance.get("gain"),
            quality_score=quality_score,
            security_vulnerabilities=security_vulnerabilities,
            semantic_equivalence=equivalence.equivalent,
        )

        manifest = self.build_manifest(
            old_code,
            new_code,
            normalized_suite,
            pricing,
            repetitions,
            seeds,
            delta,
        )

        return AuditReport(
            manifest=manifest,
            performance=performance,
            equivalence=equivalence.to_dict(),
            costs=costs.to_dict() if costs else None,
            quality_score=quality_score,
            security_vulnerabilities=security_vulnerabilities,
            overall_efficiency_score=overall,
            paired=paired.to_dict() if paired is not None else None,
            quality_floor=quality_floor,
        )
