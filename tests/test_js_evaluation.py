from __future__ import annotations

import unittest

from sia.js_evaluation import JsEvaluationEngine
from sia.models import (
    ChangeProposal,
    ExecutionResult,
    SafetyCheckResult,
    Task,
)


class JsEvaluationEngineTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = JsEvaluationEngine()

    def test_count_security_vulnerabilities_clean(self) -> None:
        code = "function add(a, b) { return a + b; }"
        self.assertEqual(self.engine.count_security_vulnerabilities(code), 0)

    def test_count_security_vulnerabilities_dangerous(self) -> None:
        code = "const fs = require('fs'); eval('1+1'); process.exit(1);"
        self.assertGreaterEqual(self.engine.count_security_vulnerabilities(code), 3)

    def test_calculate_overall_efficiency_score(self) -> None:
        good = self.engine.calculate_overall_efficiency_score(
            quality_score=1.0,
            security_vulnerabilities=0,
            semantic_equivalence=True,
        )
        bad = self.engine.calculate_overall_efficiency_score(
            quality_score=1.0,
            security_vulnerabilities=5,
            semantic_equivalence=False,
        )
        self.assertGreater(good, bad)

    def test_evaluate_sets_overall_efficiency_score(self) -> None:
        task = Task(
            description="Optimize",
            target_path="sum.js",
            current_code="function sum(a, b) { return a + b; }",
            target_symbol="sum",
        )
        proposal = ChangeProposal(
            task_id=task.task_id,
            new_code="function sum(a, b) { return a + b; }",
        )
        safety = SafetyCheckResult(approved=True, violations=(), warnings=())
        execution = ExecutionResult(success=True, exit_code=0)

        result = self.engine.evaluate(task, proposal, safety, execution)

        self.assertIsNotNone(result.overall_efficiency_score)
        self.assertTrue(0.0 <= result.overall_efficiency_score <= 1.0)


if __name__ == "__main__":
    unittest.main()
