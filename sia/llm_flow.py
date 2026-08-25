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
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from .cost_model import CostModel, PricingConfig, SavingsResult
from .evaluation_engine import resolve_confidence, wilson_confidence_interval
from .statistics import non_inferiority_test
from .models import EquivalenceReport


# Допуск реплея по умолчанию: доля элементов, которой независимый повторитель
# разрешает отличаться от записанных ответов. Основание — измерение
# воспроизводимости 2026-08-23 (см. preregistration_commitment). Переопределяется
# ключом flow "replay_tolerance"; значение попадает в обязательство до прогона.
DEFAULT_REPLAY_TOLERANCE = 0.05

# Правило учёта допуска реплея (в обязательстве с sia-preregistration/2).
# Скалярная доля не различает направление расхождения: честный повторитель
# получает дрейф симметрично в обе стороны, подлог толкает только в
# выгодную. Поэтому поэлементные расхождения считаются раздельно —
# сдвигающие результат К заявлению аудита (новый прошёл там, где записан
# провал, либо старый упал там, где записан успех) и от него — и порог
# применяется к односторонней доле «к заявлению». При том же числе 0.05
# это заметно строже к подлогу: односторонняя доля подделки примерно
# вдвое меньше двусторонней, комфорт честного повторителя сохраняется.
REPLAY_TOLERANCE_RULE = "directional-one-sided:toward-claim"


class _CheckpointJournal:
    """JSONL-журнал испытаний для возобновления длинных живых прогонов.

    Зачем: на общем бесплатном пуле таймауты и 429 штатны (проверено
    live-проверкой каталога), а длинный проб без сохранения — рулетка:
    один обрыв на 180-м вызове теряет всё. Формат: первая строка —
    заголовок {protocol, checker, dataset_sha256, endpoint, repetitions},
    далее по строке на ЗАВЕРШЁННЫЙ вызов {item, rep, ok, in, out, latency,
    usd, smodel, sfp}; smodel/sfp — отпечаток обслужившего бэкенда.
    Каждая строка fsync'ится немедленно. Падение процесса по ЛЮБОЙ причине
    теряет максимум текущий вызов.

    Возобновление отказывает при несовпадении датасета, конфигурации,
    числа повторений или ИДЕНТИЧНОСТИ ЧЕКЕРА (заголовок несёт CHECKER_ID):
    иначе доигрывание молча смешало бы результаты двух разных прогонов или
    двух разных метрик — аудит утверждал бы то, чего не измерял.
    """

    # /2: семантика чекера сменилась (ANSWER= стал якориться к последней
    # строке), а dataset_sha256 хеширует только текст промпта и ожидания —
    # смену метрики он не видит. Журналы /1 (префиксный чекер) обязаны
    # отвергаться, иначе один аудит смешает две метрики.
    # /3: изменилась ФОРМА ЗАПИСИ — появились smodel/sfp. Заголовок форму
    # записи не хеширует и наличие полей не сверяет: /2-журнал, написанный
    # до расширения, возобновился бы молча, и агрегат «что реально
    # отвечало» покрыл бы только вызовы после обрыва — в опубликованном
    # артефакте это невидимо. Правило то же, что у CHECKER_ID ниже: смена
    # содержимого журнала обязана бампить протокол структурно, а не «по
    # памяти». /2 прожил меньше суток и валидных журналов не оставил.
    PROTOCOL = "llm-flow-checkpoint/3"
    # Идентичность чекера в самом заголовке: следующая смена семантики
    # отловится сравнением заголовков автоматически, а не по памяти о бампе.
    # ПРАВИЛО: любое изменение _expect_met обязано менять эту строку.
    CHECKER_ID = "expect_contains:substring+ANSWER-last-line@v2"

    def __init__(
        self,
        path: str | Path,
        dataset_sha256: str,
        endpoint: dict[str, Any],
        repetitions: int,
    ):
        self._path = Path(path)
        self._records: dict[tuple[int, int], dict[str, Any]] = {}
        header = {
            "protocol": self.PROTOCOL,
            "checker": self.CHECKER_ID,
            "dataset_sha256": dataset_sha256,
            "endpoint": endpoint,
            # Предрегистрация фиксирует repetitions — заголовок обязан
            # нести то же число, иначе доигрывание с другим R прошло бы
            # молча (отчёт не портится: ключ (item, rep), но дешевле
            # отказаться, чем объяснять)
            "repetitions": max(1, int(repetitions)),
        }

        if self._path.exists():
            self._load_existing(header)
        else:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._append_line(header)

    def _load_existing(self, header: dict[str, Any]) -> None:
        nonempty = [
            line for line in self._path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

        if not nonempty:
            # Пустой файл (например, создан и не заполнен) — начинаем заново
            self._path.write_text("", encoding="utf-8")
            self._append_line(header)
            return

        try:
            stored_header = json.loads(nonempty[0])
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Checkpoint {self._path}: header is not valid JSON"
            ) from exc

        if (
            stored_header.get("protocol") != self.PROTOCOL
            or stored_header.get("checker") != header["checker"]
            or stored_header.get("dataset_sha256") != header["dataset_sha256"]
            or stored_header.get("endpoint") != header["endpoint"]
            or stored_header.get("repetitions") != header["repetitions"]
        ):
            raise ValueError(
                f"Checkpoint {self._path} belongs to a different dataset or "
                "configuration; refusing to resume — mixing two runs would "
                "make the audit claim what it did not measure."
            )

        torn_trailing = False

        for line in nonempty[1:]:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # Оборванная последняя строка: след падения посреди записи;
                # вызов не завершился — он будет выполнен заново
                torn_trailing = True
                continue

            self._records[(record["item"], record["rep"])] = record

        if torn_trailing:
            print(
                f"WARNING: checkpoint {self._path} had an incomplete trailing "
                "line; it was dropped and the interrupted call will rerun."
            )

    def replay(self, item: int, rep: int) -> Optional[dict[str, Any]]:
        """Записанный результат испытания или None (нужно выполнять)."""
        return self._records.get((item, rep))

    def record(
        self,
        item: int,
        rep: int,
        ok: bool,
        input_tokens: int,
        output_tokens: int,
        latency_sec: float,
        usd: float,
        served_model_name: Optional[str] = None,
        system_fingerprint: Optional[str] = None,
    ) -> None:
        # Отпечатки идут в журнал вместе с результатом: после возобновления
        # агрегат «что реально отвечало» обязан покрывать ВЕСЬ прогон, а не
        # только вызовы после обрыва
        self._append_line({
            "item": item,
            "rep": rep,
            "ok": bool(ok),
            "in": input_tokens,
            "out": output_tokens,
            "latency": latency_sec,
            "usd": usd,
            "smodel": served_model_name,
            "sfp": system_fingerprint,
        })

    def _append_line(self, payload: dict[str, Any]) -> None:
        with open(self._path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


@dataclass(frozen=True)
class CompletionResult:
    """Результат одного вызова конфигурации.

    served_model_name/system_fingerprint — что РЕАЛЬНО ответило, по версии
    самого эндпоинта. Запрошенное имя модели защищает от чего угодно,
    кроме молчаливой подмены сборки провайдером посреди прогона: парность
    старой/новой стороны имеет смысл, только если каждую сторону весь прогон
    обслужив один и тот же бэкенд. У части провайдеров поля нет — тогда
    здесь None, и это честно публикуется.
    """

    text: str
    input_tokens: int
    output_tokens: int
    latency_sec: float
    served_model_name: Optional[str] = None
    system_fingerprint: Optional[str] = None


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
    # E6: явная надёжность симулятора (вероятность корректного ответа).
    # None — брать из профиля. Публичный параметр: попадает в манифест,
    # чтобы допущение о качестве в simulated-режиме было задекларировано.
    simulated_reliability: Optional[float] = None
    # E5: датировка тарифов — попадает в манифест/коммитмент, чтобы
    # заявленную экономию можно было перепроверить против цен того дня.
    prices_as_of: Optional[str] = None
    catalog_version: Optional[str] = None
    # Провенанс цены (маяк): откуда взяты числа и какой идентификатор дал
    # цену. Без них проверяющий видит модель NVIDIA по ценам, которых
    # NVIDIA не публикует, и делает вывод, что аудитор ошибся.
    price_source_url: Optional[str] = None
    priced_model_name: Optional[str] = None
    # Само раскрытие базы цены одной фразой: «эндпоинт обслуживает NVIDIA,
    # тарифы — публичный список OpenRouter для такого-то чекпоинта; те же
    # веса, другой сервинг». Раньше эта оговорка жила только в каталоге,
    # которого квитанция не содержит.
    price_basis_note: Optional[str] = None

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
            "simulated_reliability": self.simulated_reliability,
            "prices_as_of": self.prices_as_of,
            "catalog_version": self.catalog_version,
            "price_source_url": self.price_source_url,
            "priced_model_name": self.priced_model_name,
            "price_basis_note": self.price_basis_note,
        }


def _expect_met(expect: Optional[str], text: str) -> bool:
    """Проверка чекера по метрике ожидания.

    Общий случай (expect_contains): подстрока где угодно в ответе.

    Якорный случай (expect начинается с ``ANSWER=``; метрика маяка
    ``expect_contains/digit-anchored``): ПОСЛЕДНЯЯ непустая строка ответа
    обязана быть ровно ожиданием. Модель должна ЗАВЕРШИТЬ ответом —
    упоминание числа в рассуждениях посреди текста засчитано не будет.
    """
    if expect is None:
        return True

    if expect.startswith("ANSWER="):
        lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
        return bool(lines) and lines[-1] == expect.strip()

    return expect in text


class SimulatedLLMClient:
    """Детерминированный офлайн-ответчик.

    Токены и латентность моделируются от seed и промпта (латентность —
    расчётная величина, реального ожидания нет).

    E6: симуляция нетавтологична. Корректность ответа — не гарантия, а
    детерминированное испытание с объявленной надёжностью профиля
    (``reliability``): для каждого элемента датасета seeded-RNG решает,
    содержит ли ответ ожидаемую строку. При reliability < 1.0 парный тест
    реально измеряет (смоделированную) разницу качества. Надёжность —
    публичное допущение: она попадает в манифест через public_dict(),
    а отчёт несёт caveat о simulated-режиме.
    """

    PROFILES = {
        "verbose": {"tokens_factor": 3.0, "latency_per_token": 0.030, "reliability": 1.0},
        "standard": {"tokens_factor": 1.0, "latency_per_token": 0.010, "reliability": 1.0},
        "concise": {"tokens_factor": 0.45, "latency_per_token": 0.004, "reliability": 1.0},
    }

    def __init__(self, config: LLMEndpointConfig):
        if config.profile not in self.PROFILES:
            raise ValueError(f"Unknown simulated profile: {config.profile}")

        self.config = config

    def _reliability(self, profile: dict[str, float]) -> float:
        reliability = self.config.simulated_reliability
        if reliability is None:
            reliability = profile["reliability"]
        return max(0.0, min(1.0, float(reliability)))

    @staticmethod
    def _distractor(expect: str, seed_material: str) -> str:
        """Текст, который заведомо не содержит ожидаемую строку.

        Алфавит ограничен символами, отсутствующими в expect (в обоих
        регистрах), поэтому подстрока не может совпасть случайно — в том
        числе с префиксом имени модели, которого здесь намеренно нет.
        """
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789 -"
        excluded = set(expect.lower()) | set(expect.upper())
        pool = [ch for ch in alphabet if ch not in excluded] or ["?"]
        digest = hashlib.sha256(f"{seed_material}:distractor".encode("utf-8")).hexdigest()
        return "".join(pool[int(ch, 16) % len(pool)] for ch in digest[:24])

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

        # E6: корректность — испытание с объявленной надёжностью, а не гарантия.
        # В ветке неверного ответа весь текст строится из алфавита без символов
        # ожидаемой строки — иначе filler (hex) или имя модели могли бы случайно
        # её содержать, возвращая тавтологию.
        if expect is not None:
            if rng.random() < self._reliability(profile):
                filler = hashlib.sha256(f"{seed_material}:filler".encode()).hexdigest()
                if expect.startswith("ANSWER="):
                    # Якорная метрика: правильный ответ — ПОСЛЕДНЕЙ строкой
                    text = f"[{self.config.model_name}] {filler}\n{expect}"
                else:
                    text = f"[{self.config.model_name}] {expect} {filler}"
            else:
                text = self._distractor(expect, seed_material)
        else:
            body = hashlib.sha256(prompt.encode()).hexdigest()[:12]
            filler = hashlib.sha256(f"{seed_material}:filler".encode()).hexdigest()
            text = f"[{self.config.model_name}] {body} {filler}"

        return CompletionResult(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_sec=latency_sec,
            served_model_name=self.config.model_name,
            system_fingerprint="simulated",
        )


class OpenAICompatibleClient:
    """Живой клиент для OpenAI-совместимых API (lazy import openai)."""

    def __init__(
        self,
        config: LLMEndpointConfig,
        request_timeout: float = 60.0,
        max_retries: int = 8,
    ):
        from openai import OpenAI

        if not config.api_key:
            raise ValueError(f"Live endpoint {config.model_name!r} requires api_key")

        self.config = config
        # SDK сам повторяет 408/409/429/5xx с экспоненциальным backoff и
        # уважает Retry-After — замедление происходит ровно тогда, когда
        # пул занят (общий бесплатный пул NIM), и не трогает остальное время.
        # Худший случай зависшего вызова: request_timeout × (max_retries + 1)
        # ≈ 540 с при дефолтах — нормально для пакетного прогона, знать стоит.
        self._client = OpenAI(
            api_key=config.api_key,
            base_url=config.base_url,
            timeout=request_timeout,
            max_retries=max_retries,
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
            served_model_name=getattr(response, "model", None),
            system_fingerprint=getattr(response, "system_fingerprint", None),
        )


@dataclass(frozen=True)
class FlowUsage:
    """Агрегированное потребление конфигурации за аудит."""

    calls: int
    input_tokens: int
    output_tokens: int
    latency_sec: float
    total_cost_usd: float
    # Уникальные бэкенды, фактически ответившие в этом прогоне (п.3):
    # отсортированы для детерминизма отчёта
    served_model_names: tuple[str, ...] = ()
    system_fingerprints: tuple[str, ...] = ()
    # Покрытие по КАЖДОМУ из доказательств: NIM чаще всего НЕ отдаёт
    # system_fingerprint (публикуется честный 0/n), и тогда единственным
    # свидетельством постоянства бэкенда остаётся model_names — у которого
    # счётчика не было, и прогон «3 имени из 450» был бы неотличим от
    # «450 из 450». total для обоих — usage.calls.
    served_model_name_calls: int = 0
    system_fingerprint_calls: int = 0

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
            "served_model_names": list(self.served_model_names),
            "system_fingerprints": list(self.system_fingerprints),
            "served_model_name_calls": self.served_model_name_calls,
            "system_fingerprint_calls": self.system_fingerprint_calls,
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
    # E6: simulated-режим честно помечается не только меткой mode, но и
    # явным предупреждением о том, что именно симулировалось.
    caveat: Optional[str] = None

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
            "caveat": self.caveat,
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

    # /4: в обязательстве появился anchor_declaration — явное признание
    # статуса внешнего анкоринга. Правило «нет якоря — нет записи» обязано
    # жить в коде, а не в памяти операторов: POST /v1/preregistrations
    # отказывает без объявления, а его значение замораживается в леджере —
    # запись №7 от оператора, не участовавшего в этом разговоре, не сможет
    # пройти молча. /3 был отчеканен и аннулирован в один день до записи №1.
    PREREGISTRATION_PROTOCOL = "sia-preregistration/4"

    @staticmethod
    def preregistration_commitment(
        dataset: Sequence[dict[str, Any]],
        old_config: LLMEndpointConfig,
        new_config: LLMEndpointConfig,
        delta: float,
        confidence: float = 0.95,
        repetitions: int = 1,
        replay_tolerance: float = DEFAULT_REPLAY_TOLERANCE,
        anchor_declaration: Optional[str] = None,
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
            # digit-anchored: чекер якорит ожидание к концу строки ответа
            # (ANSWER=...), а не «строка где угодно»
            "metric": "expect_contains/digit-anchored",
            "delta": delta,
            "confidence": confidence,
            "repetitions": max(1, int(repetitions)),
            # Допуск реплея (раскрытие, того же рода что MDD): обслуживаемый
            # эндпоинт недетерминирован во времени даже при temperature 0 —
            # измерение 2026-08-23: поэлементный дрейф одной модели между
            # прогонами 1-4 из 90 (до 4.4%), совокупный pass rate стабилен.
            # Честный повторитель обязан допускать такую долю расхождений;
            # без предрегистрированного допуска честная проверка выглядит
            # подлогом, а настоящий подлог прячется внутри допуска.
            "replay_tolerance": max(0.0, min(1.0, float(replay_tolerance))),
            # Направленное правило учёта допуска: порог — на односторонней
            # доле «к заявлению», а не на суммарной (см. константу выше).
            "replay_tolerance_rule": REPLAY_TOLERANCE_RULE,
            # Статус внешнего анкоринга, объявленный ОПЕРАТОРОМ при
            # регистрации (например 'external-anchor' или 'unanchored').
            # API пререгистрации отказывает без явного значения; None сюда
            # попадает только с прямого вызова/пути аудита — и это видно в
            # самом обязательстве.
            "anchor_declaration": (
                anchor_declaration.strip() if anchor_declaration else None
            ),
            "endpoints": pricing,
        }

    # Обычный метод (не staticmethod): возобновлению нужен
    # self._dataset_hash для сверки заголовка чекпойнта с обязательством
    def evaluate_config(
        self,
        client: Any,
        dataset: Sequence[dict[str, Any]],
        repetitions: int,
        cost_model: CostModel,
        checkpoint: Optional[Path] = None,
    ) -> tuple[FlowUsage, list[str], int, int, list[bool]]:
        """Прогон одной конфигурации по датасету.

        Возвращает (usage, failed_labels, passed_trials, total_trials, item_passes).
        item_passes[i] = True если элемент i прошёл все повторения.
        Используется и парным аудитом, и оптимизатором (скрининг кандидатов).

        checkpoint: необязательный JSONL-журнал возобновления (см.
        _CheckpointJournal). Записанные испытания доигрываются в
        аккумуляторы без повторного вызова, новые fsync'ятся сразу —
        падение по любой причине теряет максимум текущий вызов.
        Возобновление против другого датасета/конфигурации отклоняется.
        """
        tokens_in = tokens_out = latency = 0
        total_usd = 0.0
        failed: list[str] = []
        item_passes: list[bool] = []
        total_trials = passed_trials = 0
        served_models: set[str] = set()
        served_fingerprints: set[str] = set()
        fingerprint_calls = 0
        model_name_calls = 0

        journal = None

        if checkpoint is not None:
            journal = _CheckpointJournal(
                checkpoint,
                dataset_sha256=self._dataset_hash(dataset),
                endpoint=client.config.public_dict(),
                repetitions=repetitions,
            )

        for index, item in enumerate(dataset):
            prompt = item.get("prompt", "")
            expect = item.get("expect_contains")
            label = item.get("label", f"case-{index}")

            item_passed_all = True

            for rep in range(repetitions):
                recorded = journal.replay(index, rep) if journal else None

                if recorded is not None:
                    # Доигрывание: результат уже в журнале — вызов не повторяем
                    tokens_in += recorded["in"]
                    tokens_out += recorded["out"]
                    latency += recorded["latency"]
                    total_usd += recorded["usd"]
                    ok = bool(recorded["ok"])
                    if recorded.get("smodel"):
                        served_models.add(recorded["smodel"])
                        model_name_calls += 1
                    if recorded.get("sfp") is not None:
                        served_fingerprints.add(recorded["sfp"])
                        fingerprint_calls += 1
                else:
                    result = client.complete(prompt, expect=expect)
                    tokens_in += result.input_tokens
                    tokens_out += result.output_tokens
                    latency += result.latency_sec
                    usd = cost_model.token_cost(
                        result.input_tokens, result.output_tokens
                    )
                    total_usd += usd
                    ok = _expect_met(expect, result.text)
                    if result.served_model_name:
                        served_models.add(result.served_model_name)
                        model_name_calls += 1
                    if result.system_fingerprint is not None:
                        served_fingerprints.add(result.system_fingerprint)
                        fingerprint_calls += 1

                    if journal is not None:
                        journal.record(
                            index, rep, ok,
                            result.input_tokens,
                            result.output_tokens,
                            result.latency_sec,
                            usd,
                            served_model_name=result.served_model_name,
                            system_fingerprint=result.system_fingerprint,
                        )

                if not ok:
                    item_passed_all = False

                total_trials += 1

                if ok:
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
            served_model_names=tuple(sorted(served_models)),
            system_fingerprints=tuple(sorted(served_fingerprints)),
            served_model_name_calls=model_name_calls,
            system_fingerprint_calls=fingerprint_calls,
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
        checkpoint_dir: Optional[Path] = None,
        candidate_selected_by: str = "user",
    ) -> FlowAuditReport:
        if not dataset:
            raise ValueError("Dataset must contain at least one item")

        # E6: каждый элемент датасета обязан иметь непустой expect_contains.
        # Без чекера элемент не проверяет ничего — его «прохождение»
        # тавтологично и не может участвовать в доказательстве качества.
        unchecked = [
            index
            for index, item in enumerate(dataset)
            if not (item.get("expect_contains") or "").strip()
        ]
        if unchecked:
            raise ValueError(
                "Every dataset item requires a non-empty 'expect_contains' "
                f"checker (items without one: {unchecked}). An item with no "
                "checker verifies nothing."
            )

        repetitions = max(1, int(repetitions))
        old_client = self.client_factory(old_config)
        new_client = self.client_factory(new_config)

        old_pricing = old_config.resolve_pricing(self.defaults)
        new_pricing = new_config.resolve_pricing(self.defaults)
        old_cost_model = CostModel(old_pricing)
        new_cost_model = CostModel(new_pricing)

        # Чекпойнты по стороне (old/new): заголовок каждого содержит хеш
        # датасета и public_dict() своей конфигурации; возобновление после
        # падения доигрывает записанные вызовы без повторных обращений к API.
        old_checkpoint = (
            checkpoint_dir / "llm-audit-old.jsonl" if checkpoint_dir else None
        )
        new_checkpoint = (
            checkpoint_dir / "llm-audit-new.jsonl" if checkpoint_dir else None
        )

        usage_old, old_failed, _, _, old_passes = self.evaluate_config(
            old_client, dataset, repetitions, old_cost_model,
            checkpoint=old_checkpoint,
        )
        usage_new, new_failed, passed_trials, total_trials, new_passes = self.evaluate_config(
            new_client, dataset, repetitions, new_cost_model,
            checkpoint=new_checkpoint,
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
        # П.5: R и n — бюджетные пределы, объявленные ДО прогона, а не
        # статистический вывод. Публикуются рядом с MDD, чтобы
        # чувствительность не читалась как «аудитор выбрал удобную
        # статистику»: это всё, что способен различить данный бюджет.
        equivalence["paired"]["declared_limits"] = (
            f"R={repetitions} repetitions per item over n={dataset_size} "
            "items, both fixed at preregistration; the MDD is what this "
            "budget can detect (80% power), not a quality statement."
        )

        mode = "simulated" if isinstance(new_client, SimulatedLLMClient) else "live"

        caveat: Optional[str] = None
        if mode == "simulated":
            caveat = (
                "Simulated mode: responses are produced by a deterministic "
                "offline responder, not a real model. Correctness of each "
                "answer is a seeded trial at the declared per-profile "
                "reliability (see manifest endpoints' simulated_reliability). "
                "Cost and latency figures are modeled, not measured. "
                "This report does not attest real model quality."
            )

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
            # П.3: запрошенные имена — в old/new_endpoint выше; здесь — что
            # РЕАЛЬНО отвечало. Подмена сборки провайдером посреди прогона
            # сломала бы парность незаметно; отпечатки делают её видимой.
            # fingerprint_coverage — сколько вызовов сообщили отпечаток из
            # скольких: без покрытия «одно значение в множестве» не
            # доказывает постоянство бэкенда на всём прогоне.
            "served_endpoints": {
                "old": {
                    "model_names": list(usage_old.served_model_names),
                    "system_fingerprints": list(usage_old.system_fingerprints),
                    "model_name_coverage": {
                        "reported": usage_old.served_model_name_calls,
                        "total": usage_old.calls,
                    },
                    "fingerprint_coverage": {
                        "reported": usage_old.system_fingerprint_calls,
                        "total": usage_old.calls,
                    },
                },
                "new": {
                    "model_names": list(usage_new.served_model_names),
                    "system_fingerprints": list(usage_new.system_fingerprints),
                    "model_name_coverage": {
                        "reported": usage_new.served_model_name_calls,
                        "total": usage_new.calls,
                    },
                    "fingerprint_coverage": {
                        "reported": usage_new.system_fingerprint_calls,
                        "total": usage_new.calls,
                    },
                },
            },
            # П.4: кто выбрал кандидата. Аудитор, заверяющий конфигурацию,
            # которую выбрал его собственный оптимизатор, обязан это
            # публиковать — иначе конфликт интересов невидим проверяющему.
            "candidate_selected_by": candidate_selected_by,
        }

        return FlowAuditReport(
            mode=mode,
            usage_old=usage_old,
            usage_new=usage_new,
            costs=costs,
            equivalence=equivalence,
            manifest=manifest,
            caveat=caveat,
        )
