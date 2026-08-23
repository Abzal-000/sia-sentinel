"""Savings Autopilot: автоподбор самой дешёвой конфигурации, сохраняющей качество.

Оптимизатор делает работу, которую FinOps-инженер выполняет вручную: берёт
нагрузку заказчика (датасет + чекеры) и каталог моделей-кандидатов, дёшево
отсеивает не проходящих порог качества (нижняя граница доверительного
интервала Вильсона), а затем доказывает экономию финалистов полным аудитом
против базовой конфигурации. Итог — ранжированная рекомендация и манифест,
который попадает в подписанную аттестацию Proof-of-Savings.

Этапы:
1. Скрининг: подвыборка датасета, 1 повтор — отсев по точечной оценке
   pass rate (дешёвый префильтр).
2. Догоняющий раунд: полный датасет, 1 повтор — повторный отсев; если
   выживших больше лимита, остаются самые дешёвые из доказавших качество.
3. Финал: полный аудит каждого финалиста против базовой конфигурации
   (реальные токены, латентность, доллары, эквивалентность с CI — именно
   он даёт статистическую гарантию качества).
"""
from __future__ import annotations

import datetime as _dt
import sys
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

from .config import resolve_env
from .cost_model import CostModel, PricingConfig
from .evaluation_engine import wilson_confidence_interval
from .llm_flow import (
    FlowAuditReport,
    FlowUsage,
    LLMEndpointConfig,
    LLMFlowAuditor,
)
from .model_catalog import ModelSpec
from .statistics import holm_bonferroni

OPTIMIZATION_PROTOCOL = "proof-of-savings-optimization/1"


def spec_to_endpoint(spec: ModelSpec) -> LLMEndpointConfig:
    """Каталожная спецификация -> конфигурация эндпоинта.

    api_key берётся из переменной окружения (.env учитывается); сам ключ
    в спецификацию и манифест не попадает. В simulated-режиме (без base_url)
    профиль ответчика выводится из тира, чтобы кандидаты честно
    различались по токенам и латентности.
    """
    api_key = resolve_env(spec.api_key_env) if spec.api_key_env else None

    simulated_profile = {"premium": "verbose", "economy": "concise"}.get(
        spec.tier, "standard"
    )

    return LLMEndpointConfig(
        model_name=spec.model_name,
        input_token_usd_per_m=spec.input_token_usd_per_m,
        output_token_usd_per_m=spec.output_token_usd_per_m,
        base_url=spec.base_url,
        api_key=api_key,
        profile=simulated_profile,
        prices_as_of=spec.prices_as_of,
        catalog_version=spec.catalog_version,
    )


@dataclass(frozen=True)
class OptimizationGoal:
    """Цель оптимизации: нагрузка, порог качества и бюджет прогонов."""

    dataset: tuple[dict[str, Any], ...]
    # Нижняя граница CI доли прохождений, которую обязан показать кандидат
    quality_floor: float = 0.90
    confidence: float = 0.95
    # Доля датасета для дешёвого скрининга
    screening_fraction: float = 0.5
    # Повторы в финальном аудите
    final_repetitions: int = 2
    # Сколько финалистов доходит до полного аудита
    max_finalists: int = 3

    def __post_init__(self) -> None:
        if not self.dataset:
            raise ValueError("Optimization goal requires a non-empty dataset")

        if not 0.0 < self.quality_floor <= 1.0:
            raise ValueError("quality_floor must be in (0, 1]")

        if not 0.0 < self.screening_fraction <= 1.0:
            raise ValueError("screening_fraction must be in (0, 1]")

        if self.max_finalists < 1:
            raise ValueError("max_finalists must be >= 1")

    def screening_dataset(self) -> tuple[dict[str, Any], ...]:
        """Детерминированная подвыборка: каждый k-й элемент датасета."""
        size = max(1, int(len(self.dataset) * self.screening_fraction))

        if size >= len(self.dataset):
            return self.dataset

        step = len(self.dataset) / size
        indices = sorted({int(i * step) for i in range(size)})
        return tuple(self.dataset[i] for i in indices)


@dataclass(frozen=True)
class CandidateEvaluation:
    """Результат оценки одного кандидата на этапе скрининга/отсева."""

    model_name: str
    stage: str  # "screening" | "full"
    usage: FlowUsage
    pass_rate: float
    ci_lower: float
    ci_upper: float
    failed: tuple[str, ...]
    eliminated: bool
    reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "stage": self.stage,
            "pass_rate": round(self.pass_rate, 6),
            "ci_lower": round(self.ci_lower, 6),
            "ci_upper": round(self.ci_upper, 6),
            "failed": list(self.failed),
            "unit_cost_usd": round(self.usage.unit_cost_usd, 8),
            "avg_latency_sec": round(self.usage.avg_latency_sec, 6),
            "eliminated": self.eliminated,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class OptimizationResult:
    """Итог оптимизации: рекомендация + полная трассировка отбора."""

    goal: OptimizationGoal
    baseline: LLMEndpointConfig
    baseline_usage: FlowUsage
    evaluations: tuple[CandidateEvaluation, ...]
    finalists: tuple[str, ...]
    final_audits: dict[str, FlowAuditReport]
    best: Optional[str]
    manifest: dict[str, Any]
    multiplicity_correction: Optional[dict[str, Any]] = None

    @property
    def recommendation(self) -> Optional[dict[str, Any]]:
        """Сводка по лучшей конфигурации; None — никто не доказал экономию."""
        if self.best is None:
            return None

        report = self.final_audits[self.best]
        claim = report.to_dict()["claim"]

        return {
            "model_name": self.best,
            "savings_verified": report.savings_verified,
            **claim,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": OPTIMIZATION_PROTOCOL,
            "goal": {
                "dataset_size": len(self.goal.dataset),
                "quality_floor": self.goal.quality_floor,
                "confidence": self.goal.confidence,
                "screening_fraction": self.goal.screening_fraction,
                "final_repetitions": self.goal.final_repetitions,
                "max_finalists": self.goal.max_finalists,
            },
            "baseline": {
                "model_name": self.baseline.model_name,
                "unit_cost_usd": round(self.baseline_usage.unit_cost_usd, 8),
                "avg_latency_sec": round(self.baseline_usage.avg_latency_sec, 6),
            },
            "candidates": [ev.to_dict() for ev in self.evaluations],
            "finalists": list(self.finalists),
            "final_audits": {
                name: report.to_dict() for name, report in self.final_audits.items()
            },
            "multiplicity_correction": self.multiplicity_correction,
            "recommendation": self.recommendation,
            "manifest": self.manifest,
        }


class SavingsOptimizer:
    """Перебирает каталог и находит самую дешёвую качественную конфигурацию."""

    def __init__(
        self,
        defaults: Optional[PricingConfig] = None,
        client_factory: Optional[Callable[[LLMEndpointConfig], Any]] = None,
    ):
        self.defaults = defaults or PricingConfig()
        self.client_factory = client_factory or LLMFlowAuditor._default_client_factory
        self._auditor = LLMFlowAuditor(
            defaults=self.defaults, client_factory=self.client_factory
        )

    def _evaluate(
        self,
        config: LLMEndpointConfig,
        dataset: Sequence[dict[str, Any]],
        repetitions: int,
        stage: str,
        quality_floor: float,
        confidence: float,
        strict: bool = True,
    ) -> CandidateEvaluation:
        # Недоступная/ошибочная модель не должна ронять весь прогон:
        # она отбраковывается с причиной, оптимизация идёт по остальным.
        try:
            client = self.client_factory(config)
            cost_model = CostModel(config.resolve_pricing(self.defaults))

            usage, failed, passed, total, _item_passes = self._auditor.evaluate_config(
                client, dataset, repetitions, cost_model
            )
        except Exception as exc:
            return CandidateEvaluation(
                model_name=config.model_name,
                stage=stage,
                usage=FlowUsage(0, 0, 0, 0.0, 0.0),
                pass_rate=0.0,
                ci_lower=0.0,
                ci_upper=0.0,
                failed=(),
                eliminated=True,
                reason=f"endpoint error: {exc}",
            )

        ci_lower, ci_upper = wilson_confidence_interval(
            passed, total, confidence=confidence
        )
        pass_rate = passed / total if total else 0.0

        if strict:
            # Полный датасет: точечной оценке pass rate достаточно.
            eliminated = pass_rate < quality_floor
            reason = (
                f"pass rate {pass_rate:.3f} below quality floor {quality_floor}"
                if eliminated
                else None
            )
        else:
            # A2: скрининг на малой подвыборке — дешёвый префильтр.
            # Отбраковываем только явно плохих кандидатов, у которых даже
            # верхняя граница CI ниже порога. «Неопределённые» (точечная
            # оценка ниже порога, но CI его пересекает) проходят в
            # догоняющий раунд на полном датасете. Статистическую гарантию
            # даёт финальный полный аудит, а не скрининг.
            eliminated = pass_rate < quality_floor and ci_upper < quality_floor
            reason = (
                f"pass rate {pass_rate:.3f} below quality floor {quality_floor} "
                f"(CI upper {ci_upper:.3f} also below)"
                if eliminated
                else None
            )

        return CandidateEvaluation(
            model_name=config.model_name,
            stage=stage,
            usage=usage,
            pass_rate=pass_rate,
            ci_lower=ci_lower,
            ci_upper=ci_upper,
            failed=tuple(failed),
            eliminated=eliminated,
            reason=reason,
        )

    def optimize(
        self,
        goal: OptimizationGoal,
        baseline: LLMEndpointConfig,
        candidates: Sequence[ModelSpec],
    ) -> OptimizationResult:
        if not candidates:
            raise ValueError("Optimizer requires at least one candidate")

        # E6: скрининг идёт через evaluate_config (минуя audit_flow), поэтому
        # обязательность чекеров проверяем и здесь — элемент без чекера не
        # проверяет ничего.
        unchecked = [
            index
            for index, item in enumerate(goal.dataset)
            if not (item.get("expect_contains") or "").strip()
        ]
        if unchecked:
            raise ValueError(
                "Every dataset item requires a non-empty 'expect_contains' "
                f"checker (items without one: {unchecked})."
            )

        candidate_names = {spec.model_name for spec in candidates}

        if baseline.model_name in candidate_names:
            raise ValueError(
                f"Baseline {baseline.model_name!r} must not be among candidates"
            )

        evaluations: list[CandidateEvaluation] = []
        specs_by_name = {spec.model_name: spec for spec in candidates}

        # Этап 1: дешёвый скрининг на подвыборке
        screening_dataset = goal.screening_dataset()
        survivors: list[ModelSpec] = []

        for spec in candidates:
            evaluation = self._evaluate(
                spec_to_endpoint(spec),
                screening_dataset,
                repetitions=1,
                stage="screening",
                quality_floor=goal.quality_floor,
                confidence=goal.confidence,
                strict=False,
            )
            evaluations.append(evaluation)

            if not evaluation.eliminated:
                survivors.append(spec)

        # Этап 2: полный датасет для выживших, если их всё ещё много
        if len(survivors) > goal.max_finalists:
            proven: list[tuple[ModelSpec, CandidateEvaluation]] = []

            for spec in survivors:
                evaluation = self._evaluate(
                    spec_to_endpoint(spec),
                    goal.dataset,
                    repetitions=1,
                    stage="full",
                    quality_floor=goal.quality_floor,
                    confidence=goal.confidence,
                )
                evaluations.append(evaluation)

                if not evaluation.eliminated:
                    proven.append((spec, evaluation))

            # Доказавших качество на полном датасете больше лимита —
            # остаются самые дешёвые по цене за вызов
            if len(proven) > goal.max_finalists:
                proven.sort(key=lambda pair: pair[1].usage.unit_cost_usd)

                for spec, _ in proven[goal.max_finalists:]:
                    evaluations.append(
                        CandidateEvaluation(
                            model_name=spec.model_name,
                            stage="full",
                            usage=FlowUsage(0, 0, 0, 0.0, 0.0),
                            pass_rate=0.0,
                            ci_lower=0.0,
                            ci_upper=0.0,
                            failed=(),
                            eliminated=True,
                            reason="cut: cheaper proven candidates preferred",
                        )
                    )

                proven = proven[: goal.max_finalists]

            survivors = [spec for spec, _ in proven]

        # Базовая конфигурация оценивается всегда: её стоимость — точка отсчёта
        baseline_client = self.client_factory(baseline)
        baseline_usage, _, _, _, _ = self._auditor.evaluate_config(
            baseline_client,
            goal.dataset,
            repetitions=1,
            cost_model=CostModel(baseline.resolve_pricing(self.defaults)),
        )

        # Этап 3: полный аудит финалистов против базовой конфигурации
        finalists = tuple(spec.model_name for spec in survivors)
        final_audits: dict[str, FlowAuditReport] = {}

        for spec in survivors:
            # Финальный аудит тоже устойчив: сбой одного финалиста
            # (транзиентная ошибка эндпоинта) не роняет весь прогон.
            try:
                report = self._auditor.audit_flow(
                    dataset=goal.dataset,
                    old_config=baseline,
                    new_config=spec_to_endpoint(spec),
                    repetitions=goal.final_repetitions,
                    confidence=goal.confidence,
                )
            except Exception as exc:
                evaluations.append(
                    CandidateEvaluation(
                        model_name=spec.model_name,
                        stage="final",
                        usage=FlowUsage(0, 0, 0, 0.0, 0.0),
                        pass_rate=0.0,
                        ci_lower=0.0,
                        ci_upper=0.0,
                        failed=(),
                        eliminated=True,
                        reason=f"final audit error: {exc}",
                    )
                )
                continue

            final_audits[spec.model_name] = report

        # A3: поправка на множественность. Воронка сравнивает K финалистов с
        # базовой конфигурацией — это семейство из K парных тестов. Без
        # поправки family-wise ошибка растёт как 1-(1-alpha)^K. Корректируем
        # p-значения Макнемара по Холму–Бонферрони при семейном уровне
        # alpha = 1 - confidence; финалист проходит отбор только если его
        # вердикт о качестве подтверждён после поправки.
        multiplicity_correction = self._multiplicity_correction(
            final_audits, goal.confidence
        )
        confirmed = set(multiplicity_correction["confirmed"]) if multiplicity_correction else set(final_audits)

        best: Optional[str] = None
        best_ratio = 0.0

        for name, report in final_audits.items():
            if not report.savings_verified:
                continue
            if name not in confirmed:
                continue
            if report.costs.savings_ratio > best_ratio:
                best = name
                best_ratio = report.costs.savings_ratio

        manifest = {
            "protocol": OPTIMIZATION_PROTOCOL,
            "created": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "environment": {"python": sys.version.split()[0]},
            "dataset_sha256": LLMFlowAuditor._dataset_hash(goal.dataset),
            "dataset_size": len(goal.dataset),
            "quality_floor": goal.quality_floor,
            "confidence": goal.confidence,
            "baseline_endpoint": baseline.public_dict(),
            "candidate_endpoints": [
                specs_by_name[name].to_dict() for name in finalists
            ],
            "best": best,
        }

        return OptimizationResult(
            goal=goal,
            baseline=baseline,
            baseline_usage=baseline_usage,
            evaluations=tuple(evaluations),
            finalists=finalists,
            final_audits=final_audits,
            best=best,
            manifest=manifest,
            multiplicity_correction=multiplicity_correction,
        )

    @staticmethod
    def _multiplicity_correction(
        final_audits: dict[str, FlowAuditReport],
        confidence: float,
    ) -> Optional[dict[str, Any]]:
        """Холм–Бонферрони по p-значениям Макнемара финальных аудитов.

        Возвращает блок прозрачности: семейный уровень alpha, p-значения,
        решения Холма (reject = обнаружено значимое различие) и список
        финалистов, чей вердикт подтверждён после поправки (значимого
        различия качества не обнаружено).
        """
        if len(final_audits) < 2:
            # Один финалист — семейства нет, поправка не применяется.
            return None

        names = list(final_audits)
        p_values: list[float] = []
        degraded_direction: list[bool] = []

        for name in names:
            paired = final_audits[name].equivalence.get("paired") or {}
            # Нет парного результата — нет свидетельства различия (p=1).
            p_values.append(float(paired.get("mcnemar_p", 1.0)))
            # Направление дискордантности: b>c — новое роняет больше, чем
            # чинит (деградация); c>b — новое лучше старого.
            degraded_direction.append(
                int(paired.get("b_old_pass_new_fail", 0))
                > int(paired.get("c_old_fail_new_pass", 0))
            )

        alpha = max(1e-6, 1.0 - confidence)
        rejected = holm_bonferroni(p_values, alpha=alpha)

        per_finalist = {
            name: {
                "mcnemar_p": p_values[i],
                "reject_symmetry": rejected[i],
                "degradation_direction": degraded_direction[i],
            }
            for i, name in enumerate(names)
        }
        # Финалист подтверждён, если значимое различие НЕ обнаружено, либо
        # оно обнаружено в сторону улучшения (c>b). Значимая деградация
        # (reject при b>c) снимает кандидата с отбора.
        confirmed = [
            name
            for i, name in enumerate(names)
            if not (rejected[i] and degraded_direction[i])
        ]

        return {
            "method": "holm-bonferroni",
            "family_size": len(names),
            "alpha": alpha,
            "per_finalist": per_finalist,
            "confirmed": confirmed,
        }
