from __future__ import annotations

import unittest

from sia.audit import AuditReport, ProofOfSavingsAuditor
from sia.cost_model import PricingConfig
from sia.evaluation_engine import EvaluationEngine


OLD_CODE = """
def fib(n):
    if n <= 1:
        return n
    return fib(n - 1) + fib(n - 2)
"""

NEW_CODE = """
def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
"""

SUITE = [
    "assert fib(0) == 0",
    "assert fib(1) == 1",
    "assert fib(10) == 55",
]


class ProofOfSavingsAuditorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.auditor = ProofOfSavingsAuditor(
            evaluation=EvaluationEngine(performance_iterations=50, performance_repeat=2)
        )

    def test_audit_report_structure(self) -> None:
        report = self.auditor.audit(
            old_code=OLD_CODE,
            new_code=NEW_CODE,
            function_name="fib",
            test_suite=SUITE,
            args_template=(18,),
            pricing=PricingConfig(compute_usd_per_hour=3.6),
        )

        self.assertIsInstance(report, AuditReport)

        as_dict = report.to_dict()
        self.assertEqual(as_dict["protocol"], "proof-of-savings/1")

        for section in ("manifest", "performance", "equivalence", "costs", "claim"):
            self.assertIn(section, as_dict)

        manifest = as_dict["manifest"]
        self.assertIn("environment", manifest)
        self.assertIn("old_code_sha256", manifest)
        self.assertIn("new_code_sha256", manifest)
        self.assertIn("test_suite_sha256", manifest)
        self.assertIn("pricing", manifest)

    def test_audit_detects_real_savings(self) -> None:
        report = self.auditor.audit(
            old_code=OLD_CODE,
            new_code=NEW_CODE,
            function_name="fib",
            test_suite=SUITE,
            args_template=(18,),
            pricing=PricingConfig(compute_usd_per_hour=3.6),
        )

        self.assertEqual(report.equivalence["verdict"], "equivalent")
        self.assertGreater(report.performance["gain"], 0.5)
        self.assertGreater(report.costs["savings_ratio"], 0.5)
        self.assertTrue(report.savings_verified)

    def test_audit_without_pricing_has_no_costs(self) -> None:
        report = self.auditor.audit(
            old_code=OLD_CODE,
            new_code=NEW_CODE,
            function_name="fib",
            test_suite=SUITE,
            args_template=(18,),
        )

        self.assertIsNone(report.costs)
        self.assertFalse(report.savings_verified)

    def test_audit_broken_equivalence_not_verified(self) -> None:
        broken_code = "def fib(n):\n    return 42\n"

        report = self.auditor.audit(
            old_code=OLD_CODE,
            new_code=broken_code,
            function_name="fib",
            test_suite=SUITE,
            args_template=(10,),
            pricing=PricingConfig(compute_usd_per_hour=3.6),
        )

        self.assertEqual(report.equivalence["verdict"], "degraded")
        self.assertFalse(report.savings_verified)

    def test_manifest_is_deterministic_for_same_inputs(self) -> None:
        first = self.auditor.build_manifest(
            OLD_CODE, NEW_CODE, SUITE, PricingConfig(), 1, (42,), 0.0
        )
        second = self.auditor.build_manifest(
            OLD_CODE, NEW_CODE, SUITE, PricingConfig(), 1, (42,), 0.0
        )

        stable_keys = (
            "old_code_sha256",
            "new_code_sha256",
            "test_suite_sha256",
            "repetitions",
            "seeds",
            "delta",
        )
        for key in stable_keys:
            self.assertEqual(first[key], second[key])

    def test_code_audit_uses_paired_statistics(self) -> None:
        # A1: code-путь выносит вердикт по парному тесту (Ньюкомб/Макнемар/MDD),
        # а не по старому verdict == "equivalent".
        report = self.auditor.audit(
            old_code=OLD_CODE,
            new_code=NEW_CODE,
            function_name="fib",
            test_suite=SUITE,
            args_template=(10,),
            pricing=PricingConfig(compute_usd_per_hour=3.6),
            delta=0.0,
        )

        self.assertIsNotNone(report.paired)
        paired = report.paired
        self.assertEqual(paired["n_pairs"], len(SUITE))
        self.assertEqual(paired["b_old_pass_new_fail"], 0)
        self.assertIn("mcnemar_p", paired)
        self.assertIn("minimum_detectable_difference", paired)
        self.assertIn("delta", paired)

        claim = report.to_dict()["claim"]
        self.assertEqual(claim["delta"], 0.0)
        self.assertIn("mcnemar_p", claim)
        self.assertIn("paired_ci", claim)
        self.assertIn("minimum_detectable_difference", claim)

        # delta попадает в манифест (покрывается подписью квитанции)
        self.assertEqual(report.manifest["delta"], 0.0)

    def test_code_audit_detects_regression_via_paired_test(self) -> None:
        # Новая версия роняет тест, который проходит старая: b > 0,
        # при delta=0 неинфериорность не устанавливается.
        worse_code = "def fib(n):\n    return n - 1 if n > 1 else n\n"

        report = self.auditor.audit(
            old_code=OLD_CODE,
            new_code=worse_code,
            function_name="fib",
            test_suite=SUITE,
            args_template=(10,),
            pricing=PricingConfig(compute_usd_per_hour=3.6),
            delta=0.0,
        )

        self.assertGreater(report.paired["b_old_pass_new_fail"], 0)
        self.assertFalse(report.paired["non_inferior"])
        self.assertFalse(report.savings_verified)


if __name__ == "__main__":
    unittest.main()
