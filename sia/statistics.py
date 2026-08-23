"""Корректная статистика для Proof-of-Savings: парные тесты эквивалентности.

Этот модуль заменяет наивный «Wilson CI на одной доле» методом, который
формально верен для парного дизайна аудита: одни и те же элементы датасета
прогоняются против старой и новой конфигурации, поэтому наблюдения парные.

Ключевые инструменты:

- **Интервал Ньюкомба (Newcombe hybrid score)** для разности парных долей
  ``p_new - p_old``. Это рекомендованный метод для парных бинарных данных;
  он не страдает от ошибки «перекрывающихся интервалов».
- **Точный тест Макнемара** на дискордантных парах (симметрия).
- **Тест неинфериорности**: «новое не хуже старого больше чем на δ», где δ
  объявляется ДО прогона (предрегистрация), иначе аттестация ничего не стоит.
- **Поправка Холма–Бонферрони** на мультипликативность при скрининге многих
  кандидатов.
- **Минимальная детектируемая разница (MDD)**: аудитор публикует, какое
  падение качества он в принципе способен заметить при данном n.

Все функции работают без scipy — только stdlib (math).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

# z-значения для стандартных уровней (без scipy)
_Z = {
    0.90: 1.6448536269514722,
    0.95: 1.959963984540054,
    0.99: 2.5758293035489004,
}


def _z(confidence: float) -> float:
    """z-значение для уровня доверия; для нестандартного — ближайший."""
    if confidence in _Z:
        return _Z[confidence]
    return _Z[min(_Z, key=lambda c: abs(c - confidence))]


def _z_one_sided(alpha: float) -> float:
    """z для одностороннего уровня значимости alpha (например 0.05 -> 1.645)."""
    return _z(1.0 - 2.0 * alpha) if (1.0 - 2.0 * alpha) in _Z else _z(
        min(_Z, key=lambda c: abs(c - (1.0 - 2.0 * alpha)))
    )


def wilson_ci(successes: int, total: int, confidence: float = 0.95) -> tuple[float, float]:
    """Интервал Вильсона для одной доли (вспомогательный, для Ньюкомба)."""
    if total <= 0:
        return 0.0, 1.0
    z = _z(confidence)
    p = successes / total
    denom = 1.0 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = (z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


def newcombe_paired_ci(
    b: int,
    c: int,
    n: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Интервал для разности парных долей: MOVER на дискордантных клетках.

    ВАЖНО (честное имя): это НЕ метод Newcombe (2006). У Ньюкомба
    Wilson-интервалы строятся на маргинальных долях с поправкой на
    корреляцию ψ; здесь — на дискордантных клетках p_10/p_01 без такой
    поправки, то есть MOVER-комбинация двух Wilson-интервалов. Реализованный
    канонический вариант Ньюкомба калибровался хуже на наших n, поэтому
    конструкция оставлена, ссылка исправлена.

    Args:
        b: число дискордантных пар «старое прошло, новое упало» (old=1, new=0).
        c: число дискордантных пар «старое упало, новое прошло» (old=0, new=1).
        n: общее число парных наблюдений.
        confidence: уровень доверия.

    Returns:
        (lower, upper) для разности ``p_new - p_old``.

    Разность ``p_new - p_old = p_01 - p_10 = (c - b) / n``. Интервал —
    квадратичная комбинация Wilson-границ p_10 и p_01.
    """
    if n <= 0:
        return -1.0, 1.0

    p10 = b / n  # старое прошло, новое упало
    p01 = c / n  # старое упало, новое прошло
    diff = p01 - p10

    l10, u10 = wilson_ci(b, n, confidence)
    l01, u01 = wilson_ci(c, n, confidence)

    # Нижняя граница собирается из НИЖНИХ компонентов (p01 - l01 и
    # u10 - p10), верхняя — из ВЕРХНИХ (u01 - p01 и p10 - l10). Раньше
    # в нижней стояли компоненты верхней — интервал был смещён вверх.
    lower = diff - math.sqrt((p01 - l01) ** 2 + (u10 - p10) ** 2)
    upper = diff + math.sqrt((u01 - p01) ** 2 + (p10 - l10) ** 2)

    return max(-1.0, lower), min(1.0, upper)


def _binomial_cdf(k: int, n: int, p: float = 0.5) -> float:
    """P(X <= k) для X ~ Binomial(n, p), без scipy (прямое суммирование)."""
    if n <= 0:
        return 1.0
    k = max(0, min(k, n))
    total = 0.0
    # Используем логарифмы для устойчивости при больших n
    log_p = math.log(p) if p > 0 else float("-inf")
    log_q = math.log(1 - p) if p < 1 else float("-inf")
    for i in range(k + 1):
        log_coef = math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
        total += math.exp(log_coef + i * log_p + (n - i) * log_q)
    return min(1.0, total)


def mcnemar_exact(b: int, c: int) -> float:
    """Точный двусторонний тест Макнемара на дискордантных парах.

    H0: p_10 = p_01 (симметрия). При H0 число b ~ Binomial(b+c, 0.5).
    Возвращает двусторонний p-value.
    """
    m = b + c
    if m == 0:
        return 1.0
    # Двусторонний: 2 * min(P(X <= b), P(X >= b))
    p_le = _binomial_cdf(b, m, 0.5)
    p_ge = 1.0 - _binomial_cdf(b - 1, m, 0.5)
    return min(1.0, 2.0 * min(p_le, p_ge))


@dataclass
class NonInferiorityResult:
    """Результат теста неинфериорности для парных бинарных данных."""

    non_inferior: bool
    diff: float  # p_new - p_old (точечная оценка)
    ci_lower: float
    ci_upper: float
    delta: float  # объявленный маркер неинфериорности
    confidence_level: float
    mcnemar_p: float
    n_pairs: int
    b: int  # old pass, new fail
    c: int  # old fail, new pass
    mdd: float  # минимальная детектируемая разница при данном n

    @property
    def verdict(self) -> str:
        if self.n_pairs == 0:
            return "inconclusive"

        if self.non_inferior:
            return "non_inferior"

        # CI ниже -delta — доказанно хуже. Если же CI ПРОШЁЛ, а вердикт
        # не выдан, отказали ворота MDD: данных недостаточно, и «inferior»
        # было бы таким же превышением заявления, как и ложный PASS
        if self.ci_lower > -self.delta:
            return "inconclusive"

        return "inferior"

    def to_dict(self) -> dict:
        return {
            "non_inferior": self.non_inferior,
            "verdict": self.verdict,
            "diff": self.diff,
            "ci_lower": self.ci_lower,
            "ci_upper": self.ci_upper,
            "delta": self.delta,
            "confidence_level": self.confidence_level,
            "mcnemar_p": self.mcnemar_p,
            "n_pairs": self.n_pairs,
            "b_old_pass_new_fail": self.b,
            "c_old_fail_new_pass": self.c,
            "minimum_detectable_difference": self.mdd,
        }


def minimum_detectable_difference(
    n: int,
    alpha: float = 0.05,
    power: float = 0.80,
    p_discordant: float = 0.10,
) -> float:
    """Минимальная детектируемая разница (MDD) для парного бинарного теста.

    При данном n, уровне значимости alpha и мощности (1-beta) возвращает
    наименьшую разность долей, которую тест способен обнаружить.

    Используется приближение для парных данных:
    MDD ≈ (z_alpha + z_beta) * sqrt(p_disc / n), где p_disc — доля
    дискордантных пар (консервативно p_10 + p_01).

    Аудитор публикует это число: «при n=200 мы не заметили бы падение
    качества меньше X п.п.» — это делает вердикт честным.
    """
    if n <= 0:
        return 1.0
    z_alpha = _z_one_sided(alpha)
    z_beta = _z_one_sided(1.0 - power) if (1.0 - power) > 0 else 0.84
    # Для одностороннего alpha=0.05 z=1.645; для power=0.80 z_beta=0.84
    z_beta = 0.8416212335729143 if abs(power - 0.80) < 1e-9 else z_beta
    p_disc = max(p_discordant, 1e-6)
    return (z_alpha + z_beta) * math.sqrt(p_disc / n)


def non_inferiority_test(
    old_pass: Sequence[bool],
    new_pass: Sequence[bool],
    delta: float,
    confidence: float = 0.95,
    p_discordant_assumption: float = 0.10,
) -> NonInferiorityResult:
    """Тест неинфериорности: новое не хуже старого больше чем на delta.

    Args:
        old_pass: результаты старой конфигурации по каждому элементу (True=прошёл).
        new_pass: результаты новой конфигурации по тем же элементам.
        delta: заранее объявленный маркер неинфериорности (доля, 0..1).
            «Новое допустимо хуже старого не более чем на delta».
            ДОЛЖЕН быть объявлен до прогона (предрегистрация).
        confidence: уровень доверия для интервала.
        p_discordant_assumption: НИЖНЯЯ граница доли дискордантных пар для
            MDD. Фактически используется max(допущение, наблюдённая доля):
            MDD характеризует ЭТОТ прогон, и если дискордантность выше
            допущения, публиковать MDD по допущению — занижать собственную
            слепоту (худший случай: дешёвая модель реально хуже — тот,
            ради которого аудит существует).

    Returns:
        NonInferiorityResult с вердиктом, интервалом и MDD.

    Неинфериорность устанавливается, если нижняя граница доверительного
    интервала для (p_new - p_old) больше -delta.
    """
    if len(old_pass) != len(new_pass):
        raise ValueError("old_pass and new_pass must have the same length")

    n = len(old_pass)
    b = sum(1 for o, nw in zip(old_pass, new_pass) if o and not nw)
    c = sum(1 for o, nw in zip(old_pass, new_pass) if not o and nw)

    diff = (c - b) / n if n > 0 else 0.0
    ci_lower, ci_upper = newcombe_paired_ci(b, c, n, confidence)
    mcnemar_p = mcnemar_exact(b, c)
    observed_discordant = ((b + c) / n) if n > 0 else 0.0
    mdd = minimum_detectable_difference(
        n,
        alpha=1.0 - confidence,
        power=0.80,
        p_discordant=max(p_discordant_assumption, observed_discordant),
    )

    # Неинфериорность: нижняя граница CI для (p_new - p_old) > -delta,
    # ЗАПЕРТАЯ ПО MDD: если минимально детектируемая разница больше
    # объявленного маркера, прогон статистически не мог бы заметить
    # падение на delta, и «CI прошёл» — артефакт малой выборки, а не
    # доказательство. Исключение — полная нулевая дискордантность
    # (b = c = 0): наблюдённая разность точно 0, ухудшение не видно ни
    # в одной паре; честность такого заявления обеспечивает публикуемый
    # MDD рядом. Цена решения: аудитор отказывает чаще. Продукт — это
    # достоверная квитанция, а не PASS.
    non_inferior = (
        n > 0
        and ci_lower > -delta
        and (mdd <= delta or (b == 0 and c == 0))
    )

    return NonInferiorityResult(
        non_inferior=non_inferior,
        diff=diff,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
        delta=delta,
        confidence_level=confidence,
        mcnemar_p=mcnemar_p,
        n_pairs=n,
        b=b,
        c=c,
        mdd=mdd,
    )


def holm_bonferroni(
    p_values: Sequence[float],
    alpha: float = 0.05,
) -> list[bool]:
    """Поправка Холма–Бонферрони на мультипликативность.

    Args:
        p_values: список p-значений (по одному на кандидата/гипотезу).
        alpha: семейный уровень значимости (FWER).

    Returns:
        Список булевых решений той же длины: True = гипотеза отвергнута
        (эффект значим) с учётом поправки.

    При скрининге K кандидатов без поправки family-wise ошибка
    ≈ 1 - (1-alpha)^K; при K=20, alpha=0.05 это ~64%. Холм контролирует FWER.
    """
    m = len(p_values)
    if m == 0:
        return []

    # Сортируем с сохранением индексов
    indexed = sorted(enumerate(p_values), key=lambda x: x[1])
    decisions = [False] * m

    for rank, (orig_idx, p) in enumerate(indexed):
        threshold = alpha / (m - rank)
        if p <= threshold:
            decisions[orig_idx] = True
        else:
            # Холм: как только не отвергли — все остальные тоже не отвергаем
            break

    return decisions
