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
    # E5: датировка цен. Тарифы попадают в подписанный манифест/коммитмент,
    # но без даты экономию нельзя перепроверить против «какие цены были в
    # тот день». prices_as_of — ISO-дата актуальности тарифов,
    # catalog_version — версия каталога/источника цен.
    prices_as_of: Optional[str] = None
    catalog_version: Optional[str] = None
    # E6 (сквозная проводка): надёжность детерминированного симулятора для
    # этой модели в simulated-режиме (0..1). None — из профиля. Без поля
    # simulated-демо автопилота не различали кандидатов по качеству:
    # скрининг честно выбирал самый дешёвый из одинаково «идеальных»,
    # и демо выглядело как подгонка. В live-режиме поле игнорируется
    # (реальная модель отвечает за себя) и в манифест не попадает.
    simulated_reliability: Optional[float] = None
    # Профиль симулятора кандидата (verbose/standard/concise). Исторически
    # кандидаты несли profile, а ModelSpec молча его съедал, подменяя
    # тирано-выведенным — та же семья ошибок, что и simulated_reliability.
    # None = вывести из тира (как раньше). Валидация значения — в
    # spec_to_endpoint против SimulatedLLMClient.PROFILES.
    profile: Optional[str] = None

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(f"Unknown tier: {self.tier!r} (expected one of {TIERS})")

        if self.input_token_usd_per_m < 0 or self.output_token_usd_per_m < 0:
            raise ValueError("Pricing must be non-negative")

        if self.simulated_reliability is not None and not (
            0.0 <= self.simulated_reliability <= 1.0
        ):
            raise ValueError(
                f"simulated_reliability must be within [0, 1], "
                f"got {self.simulated_reliability!r}"
            )

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
            "prices_as_of": self.prices_as_of,
            "catalog_version": self.catalog_version,
            "simulated_reliability": self.simulated_reliability,
            "profile": self.profile,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModelSpec":
        # ЛУД-ОТКАЗ на неизвестных ключах: молчаливое съедание опечатки —
        # тот же класс ошибок, что и пропавшее simulated_reliability
        # (найдено демо 2026-09-06). Известные ключи читаем явно;
        # посторонние — ошибка ввода, а не «пусть лежит».
        # modality — легитимный ключ openrouter_catalog.json (информационный,
        # решений не принимает; в спек не тянем, пока не нужен продукту).
        known = {
            "model_name", "input_token_usd_per_m", "output_token_usd_per_m",
            "provider", "base_url", "api_key_env", "tier", "context_window",
            "tags", "prices_as_of", "priced_as", "catalog_version",
            "simulated_reliability", "modality", "profile",
        }
        unknown = sorted(set(data) - known)

        if unknown:
            raise ValueError(
                f"Unknown catalog entry keys: {unknown} (typo? update the schema first)"
            )

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
            prices_as_of=data.get("prices_as_of"),
            catalog_version=data.get("catalog_version"),
            simulated_reliability=data.get("simulated_reliability"),
            profile=data.get("profile"),
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
        """Загрузка каталога из JSON.

        Формат: {"models": [ {...}, ... ]} с опциональными глобальными
        полями "prices_as_of" (ISO-дата актуальности тарифов) и
        "catalog_version" — они применяются к каждой модели, у которой
        нет собственных значений (E5).
        """
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)

        models = data.get("models")

        if not isinstance(models, list) or not models:
            raise ValueError(f"Catalog file must contain a non-empty 'models' list: {path}")

        global_prices_as_of = data.get("prices_as_of")
        global_catalog_version = data.get("catalog_version")

        specs = []
        for item in models:
            item = dict(item)
            item.setdefault("prices_as_of", global_prices_as_of)
            item.setdefault("catalog_version", global_catalog_version)
            specs.append(ModelSpec.from_dict(item))

        return cls(specs)
