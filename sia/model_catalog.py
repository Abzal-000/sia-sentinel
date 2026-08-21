"""Каталог моделей: спецификации эндпоинтов и тарифов для оптимизатора.

Оптимизатор экономии перебирает кандидатов из каталога, поэтому тарифы и
реквизиты доступа описываются декларативно (JSON), а не зашиваются в код.
api_key в каталог не попадает — только имя переменной окружения.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence

TIERS = ("premium", "mid", "economy")


@dataclass(frozen=True)
class ModelSpec:
    """Спецификация одной модели/эндпоинта."""

    model_name: str
    input_token_usd_per_m: float
    output_token_usd_per_m: float
    provider: str = "nvidia-nim"
    base_url: Optional[str] = None
    api_key_env: Optional[str] = None
    tier: str = "mid"
    context_window: Optional[int] = None
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(f"Unknown tier: {self.tier!r} (expected one of {TIERS})")

        if self.input_token_usd_per_m < 0 or self.output_token_usd_per_m < 0:
            raise ValueError("Pricing must be non-negative")

    @property
    def blended_usd_per_m(self) -> float:
        """Ориентировочная цена 1M токенов при пропорции вход:выход 3:1."""
        return 0.75 * self.input_token_usd_per_m + 0.25 * self.output_token_usd_per_m

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "provider": self.provider,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "input_token_usd_per_m": self.input_token_usd_per_m,
            "output_token_usd_per_m": self.output_token_usd_per_m,
            "tier": self.tier,
            "context_window": self.context_window,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModelSpec":
        return cls(
            model_name=data["model_name"],
            input_token_usd_per_m=float(data["input_token_usd_per_m"]),
            output_token_usd_per_m=float(data["output_token_usd_per_m"]),
            provider=data.get("provider", "nvidia-nim"),
            base_url=data.get("base_url"),
            api_key_env=data.get("api_key_env"),
            tier=data.get("tier", "mid"),
            context_window=data.get("context_window"),
            tags=tuple(data.get("tags", ())),
        )


class ModelCatalog:
    """Коллекция ModelSpec с фильтрацией и сортировкой по цене."""

    def __init__(self, specs: Sequence[ModelSpec] = ()):
        self._specs: dict[str, ModelSpec] = {}

        for spec in specs:
            self.add(spec)

    def add(self, spec: ModelSpec) -> None:
        if spec.model_name in self._specs:
            raise ValueError(f"Duplicate model in catalog: {spec.model_name}")

        self._specs[spec.model_name] = spec

    def get(self, model_name: str) -> Optional[ModelSpec]:
        return self._specs.get(model_name)

    def all(self) -> list[ModelSpec]:
        return list(self._specs.values())

    def filter(
        self,
        tags: Optional[Sequence[str]] = None,
        tiers: Optional[Sequence[str]] = None,
        exclude: Optional[Sequence[str]] = None,
    ) -> list[ModelSpec]:
        """Отбор по тегам (все должны совпасть), тирам и списку исключений."""
        wanted_tags = set(tags or ())
        wanted_tiers = set(tiers or ())
        excluded = set(exclude or ())
        result = []

        for spec in self._specs.values():
            if spec.model_name in excluded:
                continue

            if wanted_tiers and spec.tier not in wanted_tiers:
                continue

            if wanted_tags and not wanted_tags.issubset(set(spec.tags)):
                continue

            result.append(spec)

        return result

    def cheapest_first(self, specs: Optional[Sequence[ModelSpec]] = None) -> list[ModelSpec]:
        pool = list(specs) if specs is not None else self.all()
        return sorted(pool, key=lambda s: s.blended_usd_per_m)

    def __len__(self) -> int:
        return len(self._specs)

    @classmethod
    def from_json(cls, path: str | Path) -> "ModelCatalog":
        """Загрузка каталога из JSON: {"models": [ {...}, ... ]}."""
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)

        models = data.get("models")

        if not isinstance(models, list) or not models:
            raise ValueError(f"Catalog file must contain a non-empty 'models' list: {path}")

        return cls(ModelSpec.from_dict(item) for item in models)
