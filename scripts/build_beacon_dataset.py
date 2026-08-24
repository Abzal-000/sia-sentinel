#!/usr/bin/env python3
"""Собирает датасет маяка из публичного GSM8K по детерминированной процедуре.

ЗАЧЕМ ДЕТЕРМИНИРОВАННАЯ ВЫБОРКА ИЗ ПУБЛИЧНОГО ИСТОЧНИКА

Предрегистрация не даёт переставить ворота ПОСЛЕ прогона, но она не мешает
выбрать датасет, про который заранее известно, что он выгоден. Для аудитора,
чей тезис — «не верьте нам, проверьте», это разные уровни доказательства.
Поэтому маяк собирается из публичного источника по процедуре, которую любой
человек воспроизводит байт-в-байт, не доверяя SIA:

  1. Источник: GSM8K, test split, репозиторий авторов задачи (лицензия MIT).
     URL    — см. SOURCE_URL
     SHA256 — см. SOURCE_SHA256 (сверяется при запуске; несовпадение = отказ)
     строк  — см. SOURCE_LINES
  2. Итоговый ответ задачи — текст после ``####``, запятые убраны.
  3. Фильтры, каждый закрывает свой канал ложного результата:
     - ответ парсится как целое неотрицательное;
     - ANSWER_MIN <= ответ <= ANSWER_MAX. Однозначные числа слишком часто
       попадаются в тексте случайно; начиная с 1000 появляется
       неоднозначность разделителя разрядов («1,000» против «1000»),
       которая давала бы провалы, не связанные с качеством модели;
     - строка ответа не встречается в тексте задачи — иначе пересказ
       условия проходит проверку, ничего не решив.
  4. Выжившие сортируются по sha256(question), по возрастанию hex.
     Намеренно не seeded-RNG: сортировка по хешу не зависит ни от версии
     Python, ни от языка, на котором проверяющий будет воспроизводить выборку.
  5. Маяк — первые N выживших. Проба жёсткости — последние PROBE выживших.
     Пересечение исключается проверкой N + PROBE <= число выживших.

ПОЧЕМУ ПРОБА ОТДЕЛЬНЫМ ФАЙЛОМ И ИЗ ХВОСТА

Перед предрегистрацией нужно знать наблюдаемую дискордантность: от неё
зависит публикуемый MDD, и при слишком малом N MDD выйдет ЗА объявленный
delta — аудит будет утверждать то, что его же разрешение не различает.
Но замерять её на элементах маяка нельзя: решение «регистрировать этот
датасет» оказалось бы принято после подглядывания в его результат.
Поэтому проба берётся из хвоста той же отсортированной выборки — правило
такое же механическое, а пересечение с маяком невозможно.

Проба НЕ предрегистрируется и НЕ идёт в леджер: это измерение мощности,
а не заявление. Выбрать N так, чтобы MDD < delta при измеренной
дискордантности, — это обычный расчёт мощности до эксперимента, и он
обязан происходить именно здесь, а не после прогона.

МЕТРИКА И ПОЧЕМУ ОТВЕТ ОБЁРНУТ В ``ANSWER=``

``expect_contains`` — регистрозависимая подстрока в сыром тексте ответа
(sia/llm_flow.py). На математике прямое ожидание «480» открывает канал
ложного «прошёл»: модель рассуждает, итог неверный, но верное число
попадается в промежуточном вычислении. Длину ответа ограничить нельзя —
живой клиент не передаёт max_tokens. Поэтому ожидается ``ANSWER=480``:
выдать эту строку при неверном итоге практически невозможно.

Побочный эффект называем прямо: метрика измеряет и арифметику, и следование
формату. Модель, не способная выдать одну строку по образцу, действительно
хуже как прямая замена, и смещение идёт в консервативную сторону — против
дешёвой модели, а не в сторону, выгодную заявлению об экономии.

ЗАПУСК

    curl -sSL -o .cache/gsm8k_test.jsonl <SOURCE_URL>
    python scripts/build_beacon_dataset.py --prices-as-of 2026-08-22

Скрипт отказывается собрать флоу, если при выбранном N публикуемый MDD не
меньше объявленного delta: такой аудит не может обосновать своё же
заявление, и запускать его нельзя.

ОПЕРАЦИОННОЕ ПРЕДУПРЕЖДЕНИЕ

sia/llm_flow.py прогоняет датасет строго последовательно и не ловит
исключений: неретраенный сбой на любом вызове теряет весь прогон, точки
возобновления нет. У живого клиента работает только дефолт OpenAI SDK
(2 повтора на 429/5xx). Поэтому: сначала проба (она же измеряет реальную
задержку на вызов), и только потом предрегистрация полного датасета —
обязательство фиксирует dataset_size, и уменьшить его после падения
означает потерять совпадение с обязательством.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sia.llm_flow import DEFAULT_REPLAY_TOLERANCE  # noqa: E402
from sia.statistics import minimum_detectable_difference  # noqa: E402

SOURCE_URL = (
    "https://raw.githubusercontent.com/openai/grade-school-math/master/"
    "grade_school_math/data/test.jsonl"
)
SOURCE_SHA256 = "3730d312f6e3440559ace48831e51066acaca737f6eabec99bccb9e4b3c39d14"
SOURCE_LINES = 1319

# Границы итогового ответа: см. фильтр 3 в докстринге.
ANSWER_MIN = 10
ANSWER_MAX = 999

PROMPT_TEMPLATE = (
    "Solve the problem. Reply with exactly one line and nothing else, in this "
    "exact form, with no spaces and no thousands separators:\n"
    "ANSWER=<integer>\n\n"
    "Problem: {question}"
)

# Допущение о дискордантности, с которым считается MDD в отчёте (то же, что
# по умолчанию в sia.statistics: фактически используется max(допущение,
# наблюдённая доля), так что это нижняя граница).
P_DISCORDANT_ASSUMPTION = 0.10


def _final_answer(answer_field: str) -> Optional[str]:
    """Итоговый ответ GSM8K — текст после ``####``, без разделителей разрядов."""
    if "####" not in answer_field:
        return None

    tail = answer_field.rsplit("####", 1)[1].strip().replace(",", "")

    return tail or None


def select_items(source_text: str) -> list[tuple[str, str, str]]:
    """Все выжившие после фильтров, отсортированные: (digest, question, final)."""
    survivors: list[tuple[str, str, str]] = []

    for line in source_text.splitlines():
        line = line.strip()

        if not line:
            continue

        record = json.loads(line)
        question = (record.get("question") or "").strip()
        final = _final_answer(record.get("answer") or "")

        if not question or final is None:
            continue

        if not re.fullmatch(r"\d+", final):
            continue

        if not ANSWER_MIN <= int(final) <= ANSWER_MAX:
            continue

        # Ответ, встречающийся в условии, проходил бы от простого пересказа.
        if final in question:
            continue

        digest = hashlib.sha256(question.encode("utf-8")).hexdigest()
        survivors.append((digest, question, final))

    survivors.sort(key=lambda row: row[0])

    return survivors


def _catalog_entry(catalog: dict[str, Any], model_name: str) -> dict[str, Any]:
    for model in catalog.get("models", []):
        if model.get("model_name") == model_name:
            return model

    available = ", ".join(m.get("model_name", "?") for m in catalog.get("models", []))
    raise SystemExit(f"Model not in catalog: {model_name}\nAvailable: {available}")


def _endpoint_block(
    entry: dict[str, Any],
    catalog_version: Optional[str],
    prices_as_of: str,
    price_source_url: Optional[str],
) -> dict[str, Any]:
    priced_as = entry.get("priced_as")
    price_note = None

    if priced_as and price_source_url:
        provider_label = "NVIDIA NIM" if entry.get("provider") == "nvidia-nim" else entry.get("provider", "the endpoint")
        price_note = (
            f"{provider_label} serves the endpoint; token prices are OpenRouter "
            f"list rates for {priced_as} as of {prices_as_of} "
            f"(source: {price_source_url}). Same released weights, different "
            "serving — anyone can regenerate the list and re-derive the claim."
        )

    return {
        "model_name": entry["model_name"],
        "base_url": entry["base_url"],
        "api_key_env": entry["api_key_env"],
        "input_token_usd_per_m": entry["input_token_usd_per_m"],
        "output_token_usd_per_m": entry["output_token_usd_per_m"],
        "temperature": 0.0,
        # Дата, на которую ОПЕРАТОР сверил цены, а не дата каталога: каталог
        # может быть устаревшим, а именно эта дата попадёт в обязательство.
        "prices_as_of": prices_as_of,
        "catalog_version": catalog_version,
        # Провенанс цены: какой платный идентификатор OpenRouter дал число
        # и откуда список. Запись №1 неизменяема — без этих полей проверяющий
        # видит модель NVIDIA по ценам, которых NVIDIA не публикует.
        "priced_model_name": priced_as,
        # _source живёт на КОРНЕ каталога, а не в записи модели; раньше это
        # поле искали в entry и провенанс цены молча выпадал в null.
        "price_source_url": price_source_url,
        # Само раскрытие базы цены одной фразой — в квитанцию. Раньше
        # оговорка «прогон на NIM, тарифы OpenRouter» жила только в _note
        # каталога, которого подписанный артефакт не содержит.
        "price_basis_note": price_note,
    }


def _short_name(model_name: str) -> str:
    return model_name.split("/")[-1].replace("-instruct", "").replace(":free", "")


def _required_n(delta: float, start: int, alpha: float) -> int:
    """Наименьшее n >= start, при котором MDD < delta."""
    n = max(start, 1)

    while minimum_detectable_difference(
        n, alpha=alpha, p_discordant=P_DISCORDANT_ASSUMPTION
    ) >= delta:
        n += 1

    return n


def _max_discordance(delta: float, n: int, alpha: float) -> float:
    """Дискордантность, до которой MDD при данном n остаётся ниже delta."""
    lo, hi = 0.0, 1.0

    for _ in range(60):
        mid = (lo + hi) / 2.0

        if minimum_detectable_difference(n, alpha=alpha, p_discordant=mid) < delta:
            lo = mid
        else:
            hi = mid

    return lo


def _dataset(selected: list[tuple[str, str, str]]) -> list[dict[str, str]]:
    return [
        {
            "label": f"gsm8k-{digest[:8]}",
            "prompt": PROMPT_TEMPLATE.format(question=question),
            "expect_contains": f"ANSWER={final}",
        }
        for digest, question, final in selected
    ]


def _build_flow(
    *,
    name: str,
    dataset: list[dict[str, str]],
    slice_note: str,
    source_items: int,
    args: argparse.Namespace,
    old_entry: dict[str, Any],
    new_entry: dict[str, Any],
    catalog_version: Optional[str],
    price_source_url: Optional[str],
) -> dict[str, Any]:
    return {
        "kind": "llm_flow",
        "name": name,
        "_provenance": {
            "source": "GSM8K test split (grade-school-math, MIT)",
            "source_url": SOURCE_URL,
            "source_sha256": SOURCE_SHA256,
            "source_items": source_items,
            "selection": (
                "final answer after '####', commas stripped; keep integer answers "
                f"in [{ANSWER_MIN}, {ANSWER_MAX}] whose digits do not occur in the "
                "question; sort survivors by sha256(question) ascending. "
                "Reproduce with scripts/build_beacon_dataset.py."
            ),
            "slice": slice_note,
            "builder": "scripts/build_beacon_dataset.py",
        },
        "delta": args.delta,
        "confidence": args.confidence,
        "repetitions": args.repetitions,
        # Допуск реплея ВПИСАН явно, а не унаследован молчаливым дефолтом:
        # обязательство записи №1 замораживает объявленное решение. При
        # направленном правиле (порог на односторонней доле «к заявлению»)
        # то же число 0.05 к подлогу заметно строже, чем было скалярное —
        # решение зафиксировано здесь, чтобы это читалось из флоу.
        "replay_tolerance": args.replay_tolerance,
        "dataset": dataset,
        "old": _endpoint_block(
            old_entry, catalog_version, args.prices_as_of, price_source_url
        ),
        "new": _endpoint_block(
            new_entry, catalog_version, args.prices_as_of, price_source_url
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=700)
    parser.add_argument("--source", default=str(REPO_ROOT / ".cache" / "gsm8k_test.jsonl"))
    parser.add_argument("--out", default=str(REPO_ROOT / "flows" / "beacon.json"))
    parser.add_argument("--catalog", default=str(REPO_ROOT / "flows" / "model_catalog.json"))
    parser.add_argument("--old-model", default="meta/llama-3.3-70b-instruct")
    parser.add_argument("--new-model", default="meta/llama-3.1-8b-instruct")
    parser.add_argument("--delta", type=float, default=0.05)
    parser.add_argument("--confidence", type=float, default=0.95)
    parser.add_argument("--repetitions", type=int, default=2)
    parser.add_argument(
        "--replay-tolerance",
        type=float,
        default=DEFAULT_REPLAY_TOLERANCE,
        help="Допуск реплея, вписываемый во флоу ЯВНО (0-1). Направленное "
        "правило считает расхождения по сторонам и применяет порог к "
        "односторонней доле «к заявлению» — при том же числе это строже "
        "к подлогу. Значение замораживается обязательством записи №1, "
        "поэтому решение принимается здесь, а не дефолтом в коде.",
    )
    parser.add_argument(
        "--probe-size",
        type=int,
        default=90,
        help="Элементов из ХВОСТА выборки в пробу жёсткости (0 — не собирать). "
        "Проба не предрегистрируется: она измеряет дискордантность и задержку "
        "до того, как N будет зафиксирован обязательством.",
    )
    parser.add_argument("--probe-out", default=str(REPO_ROOT / "flows" / "beacon_probe.json"))
    parser.add_argument(
        "--prices-as-of",
        required=True,
        help="Дата (YYYY-MM-DD), на которую сверены цены обеих моделей. "
        "Обязательна: недатированная цена делает заявление об экономии "
        "непроверяемым.",
    )
    parser.add_argument(
        "--allow-underpowered",
        action="store_true",
        help="Собрать флоу, даже если MDD >= delta (по умолчанию — отказ).",
    )
    args = parser.parse_args()

    source_path = Path(args.source)

    if not source_path.exists():
        print(
            f"FATAL: source not found: {source_path}\n"
            f"Download it first:\n  curl -sSL -o {source_path} {SOURCE_URL}",
            file=sys.stderr,
        )
        return 2

    raw = source_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()

    if digest != SOURCE_SHA256:
        print(
            "FATAL: source hash mismatch — the selection would not be "
            "reproducible from the pinned source.\n"
            f"  expected {SOURCE_SHA256}\n  actual   {digest}",
            file=sys.stderr,
        )
        return 3

    source_text = raw.decode("utf-8")
    line_count = len([ln for ln in source_text.splitlines() if ln.strip()])
    survivors = select_items(source_text)
    probe_size = max(0, args.probe_size)

    if args.count + probe_size > len(survivors):
        print(
            f"FATAL: {len(survivors)} items survive the filters, but "
            f"--count {args.count} + --probe-size {probe_size} = "
            f"{args.count + probe_size} are requested. The beacon and the probe "
            "must not overlap.",
            file=sys.stderr,
        )
        return 4

    # Тот же alpha, что в sia.statistics.non_inferiority_test: вердикт
    # читает нижнюю границу двустороннего CI, то есть односторонний тест
    # при (1-confidence)/2. Сборщик обязан советовать n и считать MDD по
    # той же конвенции, по которой аудит потом опубликует число.
    mdd_alpha = (1.0 - args.confidence) / 2.0

    mdd = minimum_detectable_difference(
        args.count,
        alpha=mdd_alpha,
        p_discordant=P_DISCORDANT_ASSUMPTION,
    )

    if mdd >= args.delta and not args.allow_underpowered:
        need = _required_n(args.delta, args.count, mdd_alpha)
        print(
            f"FATAL: at n={args.count} the published MDD is {mdd * 100:.2f} pp, "
            f"which is not below delta={args.delta * 100:.2f} pp. Such an audit "
            "cannot support its own claim.\n"
            f"Use --count {need} (or a larger delta).",
            file=sys.stderr,
        )
        return 5

    catalog = json.loads(Path(args.catalog).read_text(encoding="utf-8"))
    catalog_version = catalog.get("catalog_version")
    # _source — корневое поле каталога (откуда список цен); оно одно на
    # все модели и попадает в провенанс каждого эндпоинта флоу.
    price_source_url = catalog.get("_source")
    old_entry = _catalog_entry(catalog, args.old_model)
    new_entry = _catalog_entry(catalog, args.new_model)
    pair = f"{_short_name(args.old_model)}-vs-{_short_name(args.new_model)}"

    beacon = _build_flow(
        name=f"beacon-gsm8k{args.count}-{pair}",
        dataset=_dataset(survivors[: args.count]),
        slice_note=f"first {args.count} of {len(survivors)} survivors, by hash order",
        source_items=line_count,
        args=args,
        old_entry=old_entry,
        new_entry=new_entry,
        catalog_version=catalog_version,
        price_source_url=price_source_url,
    )

    out_path = Path(args.out)
    out_path.write_text(
        json.dumps(beacon, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    calls = args.count * max(1, args.repetitions) * 2
    max_disc = _max_discordance(args.delta, args.count, mdd_alpha)

    print(f"source     : {source_path} ({line_count} items, sha256 verified)")
    print(f"survivors  : {len(survivors)} after filters")
    print(f"beacon     : {args.count} items -> {out_path}")
    print(f"delta      : {args.delta * 100:.2f} pp (pre-declared)")
    print(
        f"MDD        : {mdd * 100:.2f} pp at n={args.count}, "
        f"p_disc={P_DISCORDANT_ASSUMPTION}; stays under delta while observed "
        f"discordance < {max_disc * 100:.1f}%"
    )
    print(f"live calls : {calls} ({args.count} items x {args.repetitions} reps x 2 configs)")
    print(f"prices     : as of {args.prices_as_of}, catalog_version {catalog_version}")

    if probe_size:
        probe = _build_flow(
            name=f"beacon-probe{probe_size}-{pair}",
            dataset=_dataset(survivors[-probe_size:]),
            slice_note=(
                f"last {probe_size} of {len(survivors)} survivors, by hash order — "
                "disjoint from the beacon by construction. Power measurement only: "
                "not for pre-registration or the ledger."
            ),
            source_items=line_count,
            args=args,
            old_entry=old_entry,
            new_entry=new_entry,
            catalog_version=catalog_version,
            price_source_url=price_source_url,
        )
        probe_path = Path(args.probe_out)
        probe_path.write_text(
            json.dumps(probe, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(
            f"probe      : {probe_size} items -> {probe_path} "
            f"({probe_size * max(1, args.repetitions) * 2} live calls). "
            "Run this FIRST; do not pre-register it."
        )

    catalog_date = catalog.get("prices_as_of")

    if catalog_date != args.prices_as_of:
        print(
            f"\nWARNING: catalog prices_as_of is {catalog_date}, you declared "
            f"{args.prices_as_of}. Confirm both models' prices against the "
            "provider's page for that date and update the catalog if they "
            "differ — the commitment carries YOUR date."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
