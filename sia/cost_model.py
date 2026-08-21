"""Модель затрат для Proof-of-Savings: переводит измерения в доллары.

Поддерживает два режима тарификации (их можно комбинировать):
- compute: $/час занятого инференс-железа (GPU/vCPU) × измеренное время прогона;
- tokens:  $/млн входных и выходных токенов LLM-конфигурации.

Цены передаются явно (PricingConfig); значения по умолчанию — консервативные
ориентиры середины 2026 года, для продакшена всегда задаются клиентом.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class PricingConfig:
    """Тарифы, по которым считается стоимость одного прогона."""

    compute_usd_per_hour: float = 2.0
    input_token_usd_per_m: float = 0.15
    output_token_usd_per_m: float = 0.60

    def to_dict(self) -> dict[str, float]:
        return {
            "compute_usd_per_hour": self.compute_usd_per_hour,
            "input_token_usd_per_m": self.input_token_usd_per_m,
            "output_token_usd_per_m": self.output_token_usd_per_m,
        }


@dataclass(frozen=True)
class SavingsResult:
    """Результат сравнения стоимости старой и новой конфигурации."""

    old_unit_cost_usd: float
    new_unit_cost_usd: float

    @property
    def savings_usd(self) -> float:
        return self.old_unit_cost_usd - self.new_unit_cost_usd

    @property
    def savings_ratio(self) -> float:
        if self.old_unit_cost_usd <= 0:
            return 0.0
        return max(0.0, self.savings_usd / self.old_unit_cost_usd)

    def savings_per(self, runs: int) -> float:
        return self.savings_usd * max(0, runs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "old_unit_cost_usd": round(self.old_unit_cost_usd, 8),
            "new_unit_cost_usd": round(self.new_unit_cost_usd, 8),
            "savings_usd": round(self.savings_usd, 8),
            "savings_ratio": round(self.savings_ratio, 6),
            "savings_usd_per_1k_runs": round(self.savings_per(1000), 4),
        }


class CostModel:
    """Считает стоимость прогонов по тарифам из PricingConfig."""

    def __init__(self, pricing: Optional[PricingConfig] = None):
        self.pricing = pricing or PricingConfig()

    def compute_cost(self, duration_sec: float) -> float:
        """Стоимость одного прогона по занятому времени железа."""
        if duration_sec is None or duration_sec < 0:
            return 0.0
        return duration_sec / 3600.0 * self.pricing.compute_usd_per_hour

    def token_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Стоимость одного вызова LLM по числу токенов."""
        input_tokens = max(0, int(input_tokens))
        output_tokens = max(0, int(output_tokens))

        input_usd = input_tokens / 1_000_000 * self.pricing.input_token_usd_per_m
        output_usd = output_tokens / 1_000_000 * self.pricing.output_token_usd_per_m

        return input_usd + output_usd

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Грубая оценка числа токенов (~4 символа на токен)."""
        if not text:
            return 0
        return max(1, len(text) // 4)

    def compare(
        self,
        old_unit_cost_usd: float,
        new_unit_cost_usd: float,
    ) -> SavingsResult:
        return SavingsResult(
            old_unit_cost_usd=old_unit_cost_usd,
            new_unit_cost_usd=new_unit_cost_usd,
        )
