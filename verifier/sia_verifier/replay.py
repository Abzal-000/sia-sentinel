"""Сравнение записи аудита с независимым повторным прогоном (Б2).

Проблема, которую закрывает модуль: replay_tolerance десятки недель был
ЗАДЕКЛАРИРОВАН в обязательстве («честный повторитель может отличаться
на 5% элементов»), но никакой код этот допуск не исполнял — проверка
проверяемости не существовала. Значение допуска стоит ровно от
инструмента, который его применяет. Это он.

Стороны сравнения:
- *record* — опубликованный отчёт (artifacts/…/report.json): исходный прогон;
- *replay* — отчёт внешнего повторителя, который САМ прогнал тот же флоу
  (audit_cli.py --flow …/beacon.json — промпты публичны, ключи его).

Правило строго по обязательству записи (sia-preregistration/4):
``replay_tolerance_rule = "directional-one-sided:toward-claim"``. Поэлементные
расхождения считаются раздельно по НАПРАВЛЕНИЮ сдвига аналогии «кто
выглядит лучше в повторе»:

К заявлению (toward-claim) — повтор делает дешёвую конфигурацию лучше
(или дорогую хуже), чем в записи:
  - старая сторона: записан проход → повтор провал;
  - новая сторона: записан провал → повтор проход.
От заявления (away) — зеркальные пары.

Порог применяется к ОДНОСТОРОННЕЙ доле «к заявлению», элемент — объект
счёта: элемент toward-расходится, если ХОТЯ БЫ одна его сторона съехала
в сторону заявления. Делим на n элементов. Именно поэтому при том же
числе 5% правило вдвое строже к подлогу: честный повторитель дрейфует
симметрично (его toward и away сравнимы величиной — измерено на записи
№1 источником: 1–4 из 90 на сторону на повтор), подлог толкает только в
одну сторону.

Отказы, оформленные как НЕПРИМЕНИМОСТЬ, а не «не прошёл»: другой датасет
(sha256 расходится), другое число повторений, датасет той же формы, но
без меток восстановить порядок невозможно — всё это делает сравнение
бессмысленным, а не провальным.

Входные данные — только публично опубликованные или подписанные поля:
датасет из флоу, метки провалов из обоих отчётов, replay_tolerance из
обязательства записи. Подмена входов не проходит молча именно потому,
что вердикт из тех же данных перевыводится независимо (rederive).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .rederive import _dataset_hash


class ReplayInapplicable(ValueError):
    """Сравнение бессмысленно (не «провалено»): другой датасет/R/метка."""


def _outcomes(report: dict[str, Any], labels: list[str]) -> dict[str, tuple[bool, bool]]:
    """Карта label -> (old_pass, new_pass) из списков провалов отчёта.

    Отчёт публикует только провалы (failed_old/failed_new); проход —
    отсутствие в списке. Элементы без метки не проверяются: отчёт
    знает только метки, поэтому немеченые элементы получить исход из
    меток невозможно — честный отказ, а не молчаливый пропуск.
    """
    eq = report.get("equivalence") or {}
    failed_old = set(eq.get("failed_old") or [])
    failed_new = set(eq.get("failed_new") or [])
    return {
        label: (label not in failed_old, label not in failed_new)
        for label in labels
    }


def _report_dataset_sha(report: dict[str, Any]) -> str | None:
    prereg = report.get("preregistration") or {}
    manifest = report.get("manifest") or {}
    return prereg.get("dataset_sha256") or manifest.get("dataset_sha256")


def _report_repetitions(report: dict[str, Any]) -> Any:
    prereg = report.get("preregistration") or {}
    return prereg.get("repetitions")


def compare_replays(
    record: dict[str, Any],
    replay: dict[str, Any],
    flow: dict[str, Any],
) -> dict[str, Any]:
    """Сравнивает повторный прогон с записью; возвращает verdict-отчёт.

    Returns dict: directions (toward/away/unchanged), per-side breakdown,
    tolerance, verdict (within_tolerance), comparisons= n, failures[].

    Raises ReplayInapplicable при принципиальном несоответствии входов.
    """
    dataset = flow.get("dataset") or []
    labels: list[str] = []
    for index, item in enumerate(dataset):
        label = item.get("label")
        if not label:
            raise ReplayInapplicable(
                f"dataset item {index} has no label — failure lists are "
                "label-keyed, unlabeled items cannot be compared"
            )
        labels.append(label)

    n = len(labels)
    if n == 0:
        raise ReplayInapplicable("empty dataset")

    # 1. Тот же датасет? Иначе сравнение бессмысленно, а не «не прошло».
    flow_sha = _dataset_hash(dataset)
    for name, report in (("record", record), ("replay", replay)):
        sha = _report_dataset_sha(report)
        if sha is not None and sha != flow_sha:
            raise ReplayInapplicable(
                f"{name} report belongs to a different dataset "
                f"({sha[:12]}… != flow {flow_sha[:12]}…)"
            )

    # 2. То же число повторений: R=1 отдельно задекларирован в
    #    declared_limits; смешивать R=1 c R>1 — сравнивать разные метрики.
    r_record = _report_repetitions(record)
    r_replay = _report_repetitions(replay)
    if r_record is not None and r_replay is not None and int(r_record) != int(r_replay):
        raise ReplayInapplicable(
            f"repetitions differ: record R={r_record}, replay R={r_replay}"
        )

    prereg = record.get("preregistration") or {}
    tolerance = float(prereg.get("replay_tolerance", 0.05))

    record_out = _outcomes(record, labels)
    replay_out = _outcomes(replay, labels)

    toward = 0  # сдвиг К заявлению: новую лучше / старую хуже записи
    away = 0    # элементы, сдвинувшиеся ОТ заявления
    side_breakdown = {
        "old_pass_to_fail": 0,  # toward (старая хуже)
        "old_fail_to_pass": 0,  # away   (старая лучше)
        "new_fail_to_pass": 0,  # toward (новая лучше)
        "new_pass_to_fail": 0,  # away   (новая хуже)
    }
    toward_labels: list[str] = []
    away_labels: list[str] = []

    for label in labels:
        r_old, r_new = record_out[label]
        p_old, p_new = replay_out[label]

        element_toward = False
        element_away = False

        if r_old and not p_old:
            side_breakdown["old_pass_to_fail"] += 1
            element_toward = True
        elif not r_old and p_old:
            side_breakdown["old_fail_to_pass"] += 1
            element_away = True

        if not r_new and p_new:
            side_breakdown["new_fail_to_pass"] += 1
            element_toward = True
        elif r_new and not p_new:
            side_breakdown["new_pass_to_fail"] += 1
            element_away = True
        if element_toward:
            toward += 1
            toward_labels.append(label)
        elif element_away:
            away += 1
            away_labels.append(label)

    toward_share = toward / n
    within = toward_share <= tolerance

    return {
        "rule": "directional-one-sided:toward-claim",
        "explanation": (
            "An element counts as TOWARD if at least one side shifted in "
            "favor of the claim (new config looks better / old looks worse "
            "than in the record); AWAY is the mirror. The tolerance applies "
            "to the one-sided toward share: honest replayers drift "
            "symmetrically, a forger pushes one way."
        ),
        "n_elements": n,
        "toward_elements": toward,
        "away_elements": away,
        "toward_share": toward_share,
        "away_share": away / n,
        "side_breakdown": side_breakdown,
        "tolerance": tolerance,
        "within_tolerance": within,
        "toward_labels": toward_labels,
        "away_labels": away_labels,
    }


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sia-replay",
        description=(
            "Compare an independent replay run against a published record "
            "(Б2: the replay_tolerance field finally enforced)."
        ),
    )
    parser.add_argument(
        "--flow", type=Path, required=True,
        help="The flow JSON (public; supplies dataset labels in order)",
    )
    parser.add_argument(
        "--record", type=Path, required=True,
        help="The published report.json of the original run",
    )
    parser.add_argument(
        "--replay", type=Path, required=True,
        help="The outsider's own report from re-running the same flow",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    flow = _load(args.flow)
    record = _load(args.record)
    replay = _load(args.replay)

    try:
        result = compare_replays(record, replay, flow)
    except ReplayInapplicable as exc:
        print(f"INAPPLICABLE: {exc}")
        return 2

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"elements:           {result['n_elements']}")
        print(f"toward claim:       {result['toward_elements']} "
              f"({result['toward_share']:.2%})")
        print(f"away from claim:    {result['away_elements']} "
              f"({result['away_share']:.2%})")
        print(f"side breakdown:     {result['side_breakdown']}")
        print(f"tolerance:          {result['tolerance']:.2%} (one-sided, toward-claim)")
        print(f"VERDICT:            {'WITHIN TOLERANCE' if result['within_tolerance'] else 'REPLAY MISMATCH'}")

    return 0 if result["within_tolerance"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
