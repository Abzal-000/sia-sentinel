#!/usr/bin/env python3
"""
Demo: Proof-of-Savings — проверяемое доказательство экономии.

Полный цикл продукта на одном примере (без внешних сервисов):
1. Аудит пары «старая/новая конфигурация»: замер, эквивалентность с CI, $.
2. Квитанция Ed25519 с манифестом воспроизводимости.
3. Публичная верификация квитанции (без секретного ключа).
4. Tamper-тест: подделка манифеста ломает подпись.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sia.audit import ProofOfSavingsAuditor
from sia.cost_model import PricingConfig
from sia.evaluation_engine import EvaluationEngine
from sentinel.cryptographic_receipts import ReceiptGenerator, ReceiptVerifier

OLD_CODE = '''def fib(n):
    if n <= 1:
        return n
    return fib(n - 1) + fib(n - 2)
'''

NEW_CODE = '''def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
'''

TEST_SUITE = [
    "assert fib(0) == 0",
    "assert fib(1) == 1",
    "assert fib(5) == 5",
    "assert fib(10) == 55",
    "assert fib(20) == 6765",
]


def main() -> None:
    print("=" * 70)
    print("SIA Proof-of-Savings: верифицируемая экономия для AI-нагрузок")
    print("=" * 70)
    print()

    # ===== ШАГ 1: Аудит =====
    print("ШАГ 1: Аудит пары конфигураций (замер + эквивалентность + $)")
    print("-" * 70)

    pricing = PricingConfig(compute_usd_per_hour=3.6)
    print(f"Тарифы: {json.dumps(pricing.to_dict())}")
    print()

    auditor = ProofOfSavingsAuditor(
        evaluation=EvaluationEngine(
            performance_iterations=100,
            performance_repeat=2,
            benchmark_timeout=60.0,
        )
    )
    report = auditor.audit(
        old_code=OLD_CODE,
        new_code=NEW_CODE,
        function_name="fib",
        test_suite=TEST_SUITE,
        args_template=(20,),
        pricing=pricing,
        confidence=0.95,
        repetitions=2,
        seeds=(42, 1337),
    )

    perf = report.performance
    equiv = report.equivalence
    costs = report.costs

    print(f"  Старая версия: {perf['old_time_sec'] * 1000:.3f} ms / вызов")
    print(f"  Новая версия:  {perf['new_time_sec'] * 1000:.3f} ms / вызов")
    print(f"  Ускорение:     {perf['gain']:.1%}")
    print()
    print(
        f"  Качество: {equiv['passed_new']}/{equiv['total']} тестов, "
        f"вердикт '{equiv['verdict']}'"
    )
    print(
        f"  95% CI доли проходов: [{equiv['ci_lower']:.3f}, {equiv['ci_upper']:.3f}] "
        f"({equiv['repetitions']} повтор.)"
    )
    print()
    print(f"  Стоимость/прогон: ${costs['old_unit_cost_usd']:.6f} -> ${costs['new_unit_cost_usd']:.6f}")
    print(f"  Экономия:         {costs['savings_ratio']:.1%} "
          f"(${costs['savings_usd_per_1k_runs']:.2f} на 1000 прогонов)")
    print()
    print(f"  Экономия ПОДТВЕРЖДЕНА: {report.savings_verified}")
    print()

    # ===== ШАГ 2: Квитанция с манифестом =====
    print("ШАГ 2: Квитанция Ed25519 с манифестом воспроизводимости")
    print("-" * 70)

    generator = ReceiptGenerator("demo-proof-of-savings-key")
    receipt = generator.generate_receipt(
        evidence_id="pos-demo-001",
        code=json.dumps(report.to_dict(), sort_keys=True),
        safety_approved=report.savings_verified,
        trust_level="JUNIOR",
        manifest=report.manifest,
    )

    print(f"  Receipt ID: {receipt.receipt_id[:24]}...")
    print(f"  Подпись:    {receipt.signature[:24]}...")
    print(f"  Манифест:   python {receipt.manifest['environment']['python']}, "
          f"seeds={receipt.manifest['seeds']}, "
          f"pricing={receipt.manifest['pricing']['compute_usd_per_hour']}$ / час")
    print()

    # ===== ШАГ 3: Публичная верификация =====
    print("ШАГ 3: Публичная верификация (только публичный ключ)")
    print("-" * 70)

    public_key = generator.get_public_key()
    print(f"  Публичный ключ: {public_key[:24]}...")
    print(f"  Секретный ключ недоступен проверяющему.")
    print()

    verifier = ReceiptVerifier(public_key)
    print(f"  Квитанция валидна: {verifier.verify(receipt)}")
    print()

    # ===== ШАГ 4: Tamper-тест =====
    print("ШАГ 4: Подделка манифеста")
    print("-" * 70)

    receipt.manifest["pricing"]["compute_usd_per_hour"] = 0.01
    print(f"  Изменён тариф в манифесте -> подпись сломана: "
          f"{not verifier.verify(receipt)}")
    print()

    print("=" * 70)
    print("Выводы:")
    print("  1. Экономия измерена и переведена в доллары по явным тарифам")
    print("  2. Неизменность качества доказана тестами с 95% CI (не LLM-судьёй)")
    print("  3. Доказательство подписано и проверяемо публично")
    print("  4. Манифест привязывает доказательство к окружению и данным")
    print("=" * 70)


if __name__ == "__main__":
    main()
