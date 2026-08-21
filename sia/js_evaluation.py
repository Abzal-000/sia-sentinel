from __future__ import annotations

import json
from typing import Any, Optional

from .models import (
    ChangeProposal,
    EvaluationResult,
    ExecutionResult,
    SafetyCheckResult,
    Task,
)
from .evaluation_engine import EvaluationEngine
from .js_constitutional import JsConstitutionalLayer
from .js_sandbox import JsSandboxExecutor


class JsEvaluationEngine:
    """Evaluation Engine для JavaScript-кода. Использует Node.js sandbox."""

    def __init__(
        self,
        performance_iterations: int = 2000,
        performance_repeat: int = 5,
        sandbox_timeout: int = 30,
    ) -> None:
        self.performance_iterations = performance_iterations
        self.performance_repeat = performance_repeat
        self.sandbox_executor = JsSandboxExecutor(timeout_sec=sandbox_timeout)
        self.constitutional_layer = JsConstitutionalLayer()
        # Единая формула overall-скора с Python-движком
        self._metrics = EvaluationEngine()

    def compare_performance(
        self,
        old_code: str,
        new_code: str,
        function_name: str,
        args_template: Optional[tuple[Any, ...]] = None,
    ) -> float:
        """Сравнивает производительность старой и новой JS-функций."""
        old_time = self._measure_js(old_code, function_name, args_template)
        new_time = self._measure_js(new_code, function_name, args_template)

        if old_time is None or new_time is None or old_time <= 0:
            return 0.0

        return (old_time - new_time) / old_time

    def _measure_js(
        self,
        code: str,
        function_name: str,
        args_template: Optional[tuple[Any, ...]],
    ) -> Optional[float]:
        """Измеряет время выполнения JS-функции в Node.js sandbox."""
        args_json = json.dumps(list(args_template or []))

        # Простой подход: eval в глобальном scope (требует, process доступны)
        benchmark_code = f"""
const solutionCode = {json.dumps(code)};
const functionName = {json.dumps(function_name)};
const args = {args_json};
const iterations = {self.performance_iterations};
const repeat = {self.performance_repeat};

try {{
    eval(solutionCode);
}} catch (e) {{
    console.error("IMPORT_ERROR: " + e.message);
    process.exit(2);
}}

const func = eval(functionName);
if (typeof func !== "function") {{
    console.error("FUNCTION_NOT_FOUND: " + functionName);
    process.exit(3);
}}

// Warmup
try {{
    func.apply(null, args);
}} catch (e) {{
    console.error("WARMUP_ERROR: " + e.message);
    process.exit(4);
}}

// Benchmark
const times = [];
for (let r = 0; r < repeat; r++) {{
    const start = process.hrtime.bigint();
    for (let i = 0; i < iterations; i++) {{
        func.apply(null, args);
    }}
    const end = process.hrtime.bigint();
    times.push(Number(end - start) / 1e9);
}}

const minTime = Math.min(...times);
const avgTime = minTime / iterations;

console.log(JSON.stringify({{ time: avgTime, iterations: iterations, repeat: repeat }}));
"""

        result = self.sandbox_executor.run(benchmark_code, test_code=None)


        if not result.success:
            return None

        stdout_lines = (result.stdout or "").strip().split("\n")

        for line in stdout_lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if "time" in data:
                    return float(data["time"])
            except (json.JSONDecodeError, ValueError, TypeError):
                continue

        return None

    def check_semantic_equivalence_suite(
        self,
        old_code: str,
        new_code: str,
        test_suite: list[str],
    ) -> dict[str, Any]:
        """Проверяет семантическую эквивалентность через набор тестов."""
        normalized_suite = [t.strip() for t in test_suite if t and t.strip()]

        old_failures: list[str] = []
        new_failures: list[str] = []

        for test in normalized_suite:
            if not self._run_js_tests(old_code, test):
                old_failures.append(test)
            if not self._run_js_tests(new_code, test):
                new_failures.append(test)

        total = len(normalized_suite)
        passed_old = total - len(old_failures)
        passed_new = total - len(new_failures)

        equivalent = total > 0 and not old_failures and not new_failures

        return {
            "equivalent": equivalent,
            "total": total,
            "passed_old": passed_old,
            "passed_new": passed_new,
            "failed_old": old_failures,
            "failed_new": new_failures,
            "new_only_failures": [t for t in new_failures if t not in old_failures],
            "pass_rate_old": (passed_old / total) if total else 0.0,
            "pass_rate_new": (passed_new / total) if total else 0.0,
        }

    def _run_js_tests(self, code: str, test_code: str) -> bool:
        """Запускает один JS-тест в sandbox."""
        result = self.sandbox_executor.run(code, test_code=test_code)
        return result.success

    def calculate_safety_score(self, safety_result, execution_result) -> float:
        score = 1.0
        violations = safety_result.violations or ()
        warnings = safety_result.warnings or ()
        score -= len(violations) * 0.2
        score -= len(warnings) * 0.05
        if not execution_result.success:
            score -= 0.3
        if execution_result.timed_out:
            score -= 0.5
        return max(0.0, min(1.0, score))

    def calculate_quality_score(self, code: str) -> float:
        lines = len(code.splitlines())
        score = 1.0
        if lines > 100:
            score -= 0.2
        elif lines > 50:
            score -= 0.1
        return max(0.0, min(1.0, score))

    def count_security_vulnerabilities(self, code: str) -> int:
        """Считает опасные паттерны через конституционный слой JS."""
        result = self.constitutional_layer.check(code)
        return len(result.violations)

    def calculate_overall_efficiency_score(
        self,
        performance_gain: Optional[float] = None,
        quality_score: Optional[float] = None,
        security_vulnerabilities: Optional[int] = None,
        semantic_equivalence: Optional[bool] = None,
    ) -> float:
        """Единая взвешенная метрика эффективности (как в Python-движке)."""
        return self._metrics.calculate_overall_efficiency_score(
            performance_gain=performance_gain,
            quality_score=quality_score,
            security_vulnerabilities=security_vulnerabilities,
            semantic_equivalence=semantic_equivalence,
        )

    def evaluate(
        self,
        task: Task,
        proposal: ChangeProposal,
        safety_result: SafetyCheckResult,
        execution_result: ExecutionResult,
        test_code: Optional[str] = None,
        test_suite: Optional[list[str]] = None,
        args_template: Optional[tuple[Any, ...]] = None,
        kwargs_template: Optional[dict[str, Any]] = None,
    ) -> EvaluationResult:
        """Полная оценка JavaScript-кода (совместимо с EvaluationEngine)."""
        if not safety_result.approved:
            return EvaluationResult(
                task_id=task.task_id,
                approved=False,
                details={"reason": "Safety check failed"},
            )

        if not execution_result.success:
            return EvaluationResult(
                task_id=task.task_id,
                approved=False,
                details={"reason": "Execution failed"},
            )

        function_name = task.target_symbol

        performance_gain = None
        semantic_equivalence = None
        benchmark_pass_rate = None
        semantic_test_results = None

        if function_name and args_template:
            try:
                performance_gain = self.compare_performance(
                    task.current_code,
                    proposal.new_code,
                    function_name,
                    args_template=args_template,
                )
            except Exception:
                performance_gain = None

        effective_suite: list[str] = []
        if test_suite:
            effective_suite.extend(test_suite)
        if test_code and not effective_suite:
            effective_suite.append(test_code)

        if effective_suite and function_name:
            semantic_test_results = self.check_semantic_equivalence_suite(
                task.current_code,
                proposal.new_code,
                effective_suite,
            )
            semantic_equivalence = bool(semantic_test_results["equivalent"])
            benchmark_pass_rate = float(semantic_test_results["pass_rate_new"])

        safety_score = self.calculate_safety_score(safety_result, execution_result)
        quality_score = self.calculate_quality_score(proposal.new_code)
        security_vulnerabilities = self.count_security_vulnerabilities(proposal.new_code)
        overall_efficiency_score = self.calculate_overall_efficiency_score(
            performance_gain=performance_gain,
            quality_score=quality_score,
            security_vulnerabilities=security_vulnerabilities,
            semantic_equivalence=semantic_equivalence,
        )

        approved = (
            safety_result.approved
            and execution_result.success
            and (semantic_equivalence is None or semantic_equivalence)
        )

        return EvaluationResult(
            task_id=task.task_id,
            approved=approved,
            performance_gain=performance_gain,
            safety_score=safety_score,
            benchmark_pass_rate=benchmark_pass_rate,
            semantic_equivalence=semantic_equivalence,
            semantic_test_results=semantic_test_results,
            quality_score=quality_score,
            security_vulnerabilities=security_vulnerabilities,
            overall_efficiency_score=overall_efficiency_score,
            details={
                "execution_duration": execution_result.duration_sec,
                "model_name": proposal.model_name,
            },
        )
