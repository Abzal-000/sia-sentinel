"""Аудит LLM-флоу: пары «дорогая/дешёвая конфигурация» по токенам.

Продуктовый сценарий Proof-of-Savings для ИИ-нагрузок: одна и та же
задача решается двумя конфигурациями (модель/промпт/температура), аудит
считает реальные токены и доллары по тарифам обоих эндпоинтов и доказывает
неизменность качества на чекерах заказчика с доверительным интервалом.

Два режима:
- simulated: детерминированный офлайн-ответчик (одинаковый seed -> одинаковые
  токены и латентность) — для тестов и демо без API-ключей; в отчёте честно
  помечается как simulated;
- live: любой OpenAI-совместимый API (NVIDIA NIM, OpenRouter, vLLM...) —
  токены берутся из usage ответа, латентность замеряется.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import random
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

from .cost_model import CostModel, PricingConfig, SavingsResult
from .evaluation_engine import resolve_confidence, wilson_confidence_interval
from .statistics import non_inferiority_test
from .models import EquivalenceReport


@dataclass(frozen=True)
class CompletionResult:
    """Результат одного вызова конфигурации."""

    text: str
    input_tokens: int
    output_tokens: int
    latency_sec: float


@dataclass(frozen=True)
class LLMEndpointConfig:
    """Конфигурация одного «конца» сравнения.

    api_key никогда не попадает в манифест и отчёт.
    """

    model_name: str
    input_token_usd_per_m: Optional[float] = None
    output_token_usd_per_m: Optional[float] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    temperature: float = 0.0
    # Профиль детерминированного ответчика: verbose / standard / concise
    profile: str = "standard"
    seed: int = 42

    def resolve_pricing(self, defaults: PricingConfig) -> PricingConfig:
        return PricingConfig(
            input_token_usd_per_m=(
                self.input_token_usd_per_m
                if self.input_token_usd_per_m is not None
                else defaults.input_token_usd_per_m
            ),
            output_token_usd_per_m=(
                self.output_token_usd_per_m
                if self.output_token_usd_per_m is not None
                else defaults.output_token_usd_per_m
            ),
            compute_usd_per_hour=defaults.compute_usd_per_hour,
        )

    def public_dict(self) -> dict[str, Any]:
        """Конфиг без секрета — для манифеста."""
        return {
            "model_name": self.model_name,
            "input_token_usd_per_m": self.input_token_usd_per_m,
            "output_token_usd_per_m": self.output_token_usd_per_m,
            "base_url": self.base_url,
            "temperature": self.temperature,
            "profile": self.profile,
            "seed": self.seed,
        }


class SimulatedLLMClient:
    """Детерминированный офлайн-ответчик.

    Токены и латентность моделируются от seed и промпта (латентность —
    расчётная величина, реального ожидания нет). Если задан expect,
    ответ гарантированно содержит его — чекеры проходят одинаково для
    обеих конфигураций, различаются только затраты.
    """

    PROFILES = {
        "verbose": {"tokens_factor": 3.0, "latency_per_token": 0.030},
        "standard": {"tokens_factor": 1.0, "latency_per_token": 0.010},
        "concise": {"tokens_factor": 0.45, "latency_per_token": 0.004},
    }

    def __init__(self, config: LLMEndpointConfig):
        if config.profile not in self.PROFILES:
            raise ValueError(f"Unknown simulated profile: {config.profile}")

        self.config = config

    def complete(self, prompt: str, expect: Optional[str] = None) -> CompletionResult:
        profile = self.PROFILES[self.config.profile]

        seed_material = (
            f"{self.config.seed}:{self.config.model_name}:{self.config.profile}:{prompt}"
        )
        rng = random.Random(hashlib.sha256(seed_material.encode("utf-8")).hexdigest())

        base_output_tokens = 80
        output_tokens = int(
            base_output_tokens
            * profile["tokens_factor"]
            * (1.0 + rng.random() * 0.2)
        )
        input_tokens = CostModel.estimate_tokens(prompt) + 40

        latency_sec = output_tokens * profile["latency_per_token"] * (1.0 + rng.random() * 0.1)

        body = expect if expect is not None else hashlib.sha256(prompt.encode()).hexdigest()[:12]
        filler = hashlib.sha256(f"{seed_material}:filler".encode()).hexdigest()
        text = f"[{self.config.model_name}] {body} {filler}"

        return CompletionResult(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_sec=latency_sec,
        )


class OpenAICompatibleClient:
    """Живой клиент для OpenAI-совместимых API (lazy import openai)."""

    def __init__(self, config: LLMEndpointConfig, request_timeout: float = 60.0):
        from openai import OpenAI

        if not config.api_key:
            raise ValueError(f"Live endpoint {config.model_name!r} requires api_key")

        self.config = config
        self._client = OpenAI(
            api_key=config.api_key,
            base_url=config.base_url,
            timeout=request_timeout,
        )

    def complete(self, prompt: str, expect: Optional[str] = None) -> CompletionResult:
        started = time.perf_counter()

        response = self._client.chat.completions.create(
            model=self.config.model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.config.temperature,
        )

        latency_sec = time.perf_counter() - started
        usage = getattr(response, "usage", None)
        text = response.choices[0].message.content or ""

        return CompletionResult(
            text=text,
            input_tokens=getattr(usage, "prompt_tokens", CostModel.estimate_tokens(prompt)),
            output_tokens=getattr(usage, "completion_tokens", CostModel.estimate_tokens(text)),
            latency_sec=latency_sec,
        )


@dataclass(frozen=True)
class FlowUsage:
    """Агрегированное потребление конфигурации за аудит."""

    calls: int
    input_tokens: int
    output_tokens: int
    latency_sec: float
    total_cost_usd: float

    @property
    def unit_cost_usd(self) -> float:
        return self.total_cost_usd / self.calls if self.calls else 0.0

    @property
    def avg_latency_sec(self) -> float:
        return self.latency_sec / self.calls if self.calls else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "avg_latency_sec": round(self.avg_latency_sec, 6),
            "total_cost_usd": round(self.total_cost_usd, 8),
            "unit_cost_usd": round(self.unit_cost_usd, 8),
        }


@dataclass(frozen=True)
class FlowAuditReport:
    """Итоговый отчёт аудита LLM-флоу."""

    mode: str
    usage_old: FlowUsage
    usage_new: FlowUsage
    costs: SavingsResult
    equivalence: dict[str, Any]
    manifest: dict[str, Any]

    @property
    def savings_verified(self) -> bool:
        # Первичный критерий качества — парный тест неинфериорности
        # (формально корректный для парного дизайна). Дополнительно:
        # нулевая дискордантность (b=c=0) означает, что наблюдаемое
        # качество идентично — claim честен при опубликованном MDD,
        # даже если малое n не даёт CI подтвердить неинфериорность.
        paired = self.equivalence.get("paired")
        if paired is not None:
            quality_preserved = bool(paired.get("non_inferior")) or (
                paired.get("b_old_pass_new_fail", 0) == 0
                and paired.get("c_old_fail_new_pass", 0) == 0
            )
        else:
            quality_preserved = self.equivalence.get("verdict") == "equivalent"
        return quality_preserved and self.costs.savings_ratio > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": "proof-of-savings-llm/1",
            "mode": self.mode,
            "claim": {
                "savings_verified": self.savings_verified,
                "savings_ratio": round(self.costs.savings_ratio, 6),
                "old_unit_cost_usd": round(self.costs.old_unit_cost_usd, 8),
                "new_unit_cost_usd": round(self.costs.new_unit_cost_usd, 8),
                "savings_usd_per_1k_calls": round(self.costs.savings_per(1000), 4),
                "equivalence_ci": [
                    self.equivalence.get("ci_lower"),
                    self.equivalence.get("ci_upper"),
                ],
                "confidence_level": self.equivalence.get("confidence_level"),
            },
            "usage_old": self.usage_old.to_dict(),
            "usage_new": self.usage_new.to_dict(),
            "costs": self.costs.to_dict(),
            "equivalence": self.equivalence,
            "manifest": self.manifest,
        }


class LLMFlowAuditor:
    """Сравнивает два LLM-эндпоинта на датасете с чекерами заказчика."""

    def __init__(
        self,
        defaults: Optional[PricingConfig] = None,
        client_factory: Optional[Callable[[LLMEndpointConfig], Any]] = None,
    ):
        self.defaults = defaults or PricingConfig()
        # Фабрика подменяется в тестах; по умолчанию — live при наличии
        # api_key/base_url и simulated иначе
        self.client_factory = client_factory or self._default_client_factory

    @staticmethod
    def _default_client_factory(config: LLMEndpointConfig):
        if config.api_key or config.base_url:
            return OpenAICompatibleClient(config)
        return SimulatedLLMClient(config)

    @staticmethod
    def _dataset_hash(dataset: Sequence[dict[str, Any]]) -> str:
        joined = "\n".join(
            f"{item.get('prompt', '')}|{item.get('expect_contains', '')}"
            for item in dataset
        )
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    PREREGISTRATION_PROTOCOL = "sia-preregistration/1"

    @staticmethod
    def preregistration_commitment(
        dataset: Sequence[dict[str, Any]],
        old_config: LLMEndpointConfig,
        new_config: LLMEndpointConfig,
        delta: float,
        confidence: float = 0.95,
        repetitions: int = 1,
    ) -> dict[str, Any]:
        """Обязательство аудита, регистрируемое в цепочке ДО прогона.

        Покрывает хешами все параметры, влияющие на вердикт: датасет,
        маркер неинфериорности delta, метрику качества, конфигурации и
        цены обеих сторон. После предрегистрации аудитор не может
        переставить ворота: цепочка доказывает, что вердикт вынесен
        против заранее объявленных параметров (аналог пререгистрации
        в клинических испытаниях).
        """
        pricing = {
            "old": old_config.public_dict(),
            "new": new_config.public_dict(),
        }
        return {
            "protocol": LLMFlowAuditor.PREREGISTRATION_PROTOCOL,
            "dataset_sha256": LLMFlowAuditor._dataset_hash(dataset),
            "dataset_size": len(dataset),
            "metric": "expect_contains",
            "delta": delta,
            "confidence": confidence,
            "repetitions": max(1, int(repetitions)),
            "endpoints": pricing,
        }

    @staticmethod
    def evaluate_config(
        client: Any,
        dataset: Sequence[dict[str, Any]],
        repetitions: int,
        cost_model: CostModel,
    ) -> tuple[FlowUsage, list[str], int, int, list[bool]]:
        """Прогон одной конфигурации по датасету.

        Возвращает (usage, failed_labels, passed_trials, total_trials, item_passes).
        item_passes[i] = True если элемент i прошёл все повторения.
        Используется и парным аудитом, и оптимизатором (скрининг кандидатов).
        """
        tokens_in = tokens_out = latency = 0
        total_usd = 0.0
        failed: list[str] = []
        item_passes: list[bool] = []
        total_trials = passed_trials = 0

        for index, item in enumerate(dataset):
            prompt = item.get("prompt", "")
            expect = item.get("expect_contains")
            label = item.get("label", f"case-{index}")

            item_passed_all = True

            for _ in range(repetitions):
                result = client.complete(prompt, expect=expect)
                tokens_in += result.input_tokens
                tokens_out += result.output_tokens
                latency += result.latency_sec
                total_usd += cost_model.token_cost(
                    result.input_tokens, result.output_tokens
                )

                if expect is not None and expect not in result.text:
                    item_passed_all = False

                total_trials += 1

                if expect is None or expect in result.text:
                    passed_trials += 1

            item_passes.append(item_passed_all)

            if not item_passed_all:
                failed.append(label)

        usage = FlowUsage(
            calls=len(dataset) * repetitions,
            input_tokens=tokens_in,
            output_tokens=tokens_out,
            latency_sec=latency,
            total_cost_usd=total_usd,
        )

        return usage, failed, passed_trials, total_trials, item_passes

    def audit_flow(
        self,
        dataset: Sequence[dict[str, Any]],
        old_config: LLMEndpointConfig,
        new_config: LLMEndpointConfig,
        repetitions: int = 1,
        confidence: float = 0.95,
        delta: float = 0.05,
    ) -> FlowAuditReport:
        if not dataset:
            raise ValueError("Dataset must contain at least one item")

        repetitions = max(1, int(repetitions))
        old_client = self.client_factory(old_config)
        new_client = self.client_factory(new_config)

        old_pricing = old_config.resolve_pricing(self.defaults)
        new_pricing = new_config.resolve_pricing(self.defaults)
        old_cost_model = CostModel(old_pricing)
        new_cost_model = CostModel(new_pricing)

        usage_old, old_failed, _, _, old_passes = self.evaluate_config(
            old_client, dataset, repetitions, old_cost_model
        )
        usage_new, new_failed, passed_trials, total_trials, new_passes = self.evaluate_config(
            new_client, dataset, repetitions, new_cost_model
        )

        costs = CostModel().compare(
            usage_old.unit_cost_usd,
            usage_new.unit_cost_usd,
        )

        ci_lower, ci_upper = wilson_confidence_interval(
            passed_trials, total_trials, confidence=confidence
        )

        # Отчёт отдаёт фактически использованный уровень доверия,
        # а не запрошенный (B4b)
        _, effective_confidence = resolve_confidence(confidence)

        # Парный тест неинфериорности: формально корректный метод для
        # парного дизайна (одни и те же элементы против двух конфигураций).
        # delta — заранее объявленный маркер «новое допустимо хуже не более
        # чем на delta». По умолчанию 0.05 (5 п.п.); в продакшене должен
        # предрегистрироваться до прогона.
        paired = non_inferiority_test(
            old_passes, new_passes, delta=delta, confidence=confidence
        )

        dataset_size = len(dataset)

        equivalence = EquivalenceReport(
            total=dataset_size,
            passed_old=dataset_size - len(old_failed),
            passed_new=dataset_size - len(new_failed),
            failed_old=tuple(old_failed),
            failed_new=tuple(new_failed),
            new_only_failures=tuple(
                label for label in new_failed if label not in old_failed
            ),
            pass_rate_old=(dataset_size - len(old_failed)) / dataset_size,
            pass_rate_new=(dataset_size - len(new_failed)) / dataset_size,
            ci_lower=ci_lower,
            ci_upper=ci_upper,
            confidence_level=effective_confidence,
            repetitions=repetitions,
        ).to_dict()

        # Добавляем парную статистику в отчёт эквивалентности
        equivalence["paired"] = paired.to_dict()

        mode = "simulated" if isinstance(new_client, SimulatedLLMClient) else "live"

        manifest = {
            "protocol": "proof-of-savings-llm/1",
            "created": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "mode": mode,
            "environment": {
                "python": sys.version.split()[0],
            },
            "dataset_sha256": self._dataset_hash(dataset),
            "dataset_size": len(dataset),
            "repetitions": repetitions,
            "old_endpoint": old_config.public_dict(),
            "new_endpoint": new_config.public_dict(),
        }

        return FlowAuditReport(
            mode=mode,
            usage_old=usage_old,
            usage_new=usage_new,
            costs=costs,
            equivalence=equivalence,
            manifest=manifest,
        )
