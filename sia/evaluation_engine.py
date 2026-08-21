from __future__ import annotations

import ast
import json
import math
import os
import subprocess
import sys
import tempfile
import timeit
import multiprocessing
from typing import Any, Optional

from .cost_model import CostModel, PricingConfig, SavingsResult
from .models import (
    ChangeProposal,
    EquivalenceReport,
    EvaluationResult,
    ExecutionResult,
    SafetyCheckResult,
    Task,
)



def _benchmark_worker(
    code: str,
    func_name: str,
    args: tuple,
    kwargs: dict,
    repeat: int,
    iterations: int,
) -> float:
    """Воркер для измерения времени выполнения функции в отдельном процессе.

    Вынесена на уровень модуля, чтобы быть picklable на Windows.
    """

    namespace = {}
    try:
        exec(compile(code, "<string>", "exec"), namespace)
    except Exception as e:
        raise RuntimeError(f"Code compilation failed: {e}")

    func = namespace.get(func_name)
    if not callable(func):
        raise RuntimeError(f"Function '{func_name}' not found")

    times = timeit.repeat(
        lambda: func(*args, **kwargs),
        repeat=repeat,
        number=iterations,
    )
    return min(times)


def _benchmark_process(
    code: str,
    func_name: str,
    args: tuple,
    kwargs: dict,
    repeat: int,
    iterations: int,
    result_queue: "multiprocessing.Queue",
) -> None:
    """Точка входа дочернего процесса бенчмарка.

    Результат (или текст ошибки) передаётся через очередь: родитель
    ждёт его не дольше таймаута и принудительно завершает процесс,
    если код завис (например, бесконечный цикл).
    """
    try:
        result = _benchmark_worker(code, func_name, args, kwargs, repeat, iterations)
        payload = ("ok", result)
    except BaseException as exc:  # noqa: BLE001 — пробрасываем текстом, не pickle
        payload = ("error", f"{type(exc).__name__}: {exc}")

    try:
        result_queue.put(payload)
    except Exception:
        pass


# z-значения для стандартных уровней доверия (без scipy)
_Z_SCORES = {
    0.90: 1.6448536269514722,
    0.95: 1.959963984540054,
    0.99: 2.5758293035489004,
}


def resolve_confidence(confidence: float) -> tuple[float, float]:
    """Возвращает (z, фактически_использованный_уровень).

    Для нестандартного уровня берётся ближайший известный; функция
    сообщает, какой уровень реально применён, чтобы отчёт не выдавал
    запрошенный уровень за использованный (B4b).
    """
    z = _Z_SCORES.get(confidence)
    if z is not None:
        return z, confidence

    effective = min(_Z_SCORES, key=lambda level: abs(level - confidence))
    return _Z_SCORES[effective], effective


def wilson_confidence_interval(
    successes: int,
    total: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Интервал Вильсона для доли успехов (биномиальный CI без scipy)."""
    if total <= 0:
        return 0.0, 1.0

    z, _ = resolve_confidence(confidence)

    p = successes / total
    denom = 1.0 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = (z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))) / denom

    return max(0.0, center - margin), min(1.0, center + margin)


class EvaluationEngine:
    def __init__(
        self,
        performance_iterations: int = 1000,
        performance_repeat: int = 3,
        benchmark_timeout: float = 10.0,
        pricing: Optional[PricingConfig] = None,
    ) -> None:
        self.performance_iterations = performance_iterations
        self.performance_repeat = performance_repeat
        self.benchmark_timeout = benchmark_timeout
        # Тарифы для расчёта экономии в $; None — тарификация выключена
        self.cost_model = CostModel(pricing) if pricing is not None else None

    def compare_performance(
        self,
        old_code: str,
        new_code: str,
        function_name: str,
        args_template: Optional[tuple[Any, ...]] = None,
        kwargs_template: Optional[dict[str, Any]] = None,
    ) -> float:
        """Сравнивает производительность старой и новой версий функции."""
        return self.compare_performance_detailed(
            old_code,
            new_code,
            function_name,
            args_template=args_template,
            kwargs_template=kwargs_template,
        )["gain"]

    def compare_performance_detailed(
        self,
        old_code: str,
        new_code: str,
        function_name: str,
        args_template: Optional[tuple[Any, ...]] = None,
        kwargs_template: Optional[dict[str, Any]] = None,
    ) -> dict[str, Optional[float]]:
        """Замеряет обе версии и возвращает времена и прирост скорости."""
        args = args_template or ()
        kwargs = kwargs_template or {}

        # Получаем таймаут из атрибута или используем значение по умолчанию
        bench_timeout = getattr(self, 'benchmark_timeout', 10.0)

        try:
            # Передаём код и имя функции вместо готовых объектов
            old_time = self._measure_time(
                old_code,
                function_name,
                args,
                kwargs,
                timeout=bench_timeout,
            )
            new_time = self._measure_time(
                new_code,
                function_name,
                args,
                kwargs,
                timeout=bench_timeout,
            )
        except TimeoutError:
            # Отклоняем изменение при таймауте (возможный бесконечный цикл)
            return {"old_time_sec": None, "new_time_sec": None, "gain": 0.0}
        except RuntimeError:
            # Ошибка компиляции или выполнения кода
            return {"old_time_sec": None, "new_time_sec": None, "gain": 0.0}

        if old_time is None or new_time is None or old_time <= 0:
            return {"old_time_sec": old_time, "new_time_sec": new_time, "gain": 0.0}

        # _measure_time возвращает суммарное время iterations вызовов;
        # для стоимости нужен per-call интервал
        per_call_old = old_time / max(1, self.performance_iterations)
        per_call_new = new_time / max(1, self.performance_iterations)

        return {
            "old_time_sec": per_call_old,
            "new_time_sec": per_call_new,
            "gain": (old_time - new_time) / old_time,
        }

    def calculate_safety_score(
        self,
        safety_result: SafetyCheckResult,
        execution_result: ExecutionResult,
    ) -> float:
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

    def check_semantic_equivalence(
        self,
        old_code: str,
        new_code: str,
        test_code: str,
    ) -> bool:
        result = self.check_semantic_equivalence_suite(
            old_code,
            new_code,
            [test_code],
        )
        return bool(result["equivalent"])

    def check_semantic_equivalence_suite(
        self,
        old_code: str,
        new_code: str,
        test_suite: list[str],
    ) -> dict[str, Any]:
        return self.check_equivalence_with_confidence(
            old_code,
            new_code,
            test_suite,
        ).to_dict()

    def check_equivalence_with_confidence(
        self,
        old_code: str,
        new_code: str,
        test_suite: list[str],
        confidence: float = 0.95,
        repetitions: int = 1,
    ) -> EquivalenceReport:
        """Прогоняет сьют на обеих версиях и считает доверительный интервал.

        Единицей испытания является тест, а не повторение: при
        repetitions > 1 тест считается пройденным, только если новая
        версия прошла все R прогонов. Повторения снижают шанс
        случайного прохождения стохастического теста, но не создают
        новых независимых наблюдений, поэтому в интервал Вильсона
        входит len(test_suite) испытаний (B4a).

        confidence_level в отчёте — фактически использованный уровень
        (ближайший известный, если запрошен нестандартный), а не
        запрошенный (B4b).
        """
        normalized_suite = [test.strip() for test in test_suite if test and test.strip()]
        repetitions = max(1, int(repetitions))

        old_failures: list[str] = []
        new_failures: list[str] = []

        for test in normalized_suite:
            if not self._run_tests(old_code, test):
                old_failures.append(test)

            new_passed_runs = sum(
                1 for _ in range(repetitions) if self._run_tests(new_code, test)
            )

            if new_passed_runs < repetitions:
                new_failures.append(test)

        total = len(normalized_suite)
        passed_old = total - len(old_failures)
        passed_new = total - len(new_failures)

        _, effective_confidence = resolve_confidence(confidence)

        ci_lower, ci_upper = wilson_confidence_interval(
            passed_new,
            total,
            confidence=confidence,
        )

        return EquivalenceReport(
            total=total,
            passed_old=passed_old,
            passed_new=passed_new,
            failed_old=tuple(old_failures),
            failed_new=tuple(new_failures),
            new_only_failures=tuple(
                test for test in new_failures if test not in old_failures
            ),
            pass_rate_old=(passed_old / total) if total else 0.0,
            pass_rate_new=(passed_new / total) if total else 0.0,
            ci_lower=ci_lower,
            ci_upper=ci_upper,
            confidence_level=effective_confidence,
            repetitions=repetitions,
        )

    def calculate_quality_score(self, code: str) -> float:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return 0.0

        lines = len(code.splitlines())
        nested_loops = self._count_nested_loops(tree)

        score = 1.0

        if lines > 100:
            score -= 0.2
        elif lines > 50:
            score -= 0.1

        if nested_loops > 3:
            score -= 0.3
        elif nested_loops > 2:
            score -= 0.15

        return max(0.0, min(1.0, score))

    def count_security_vulnerabilities(self, code: str) -> int:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".py",
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp.write(code)
                tmp_path = tmp.name

            result = subprocess.run(
                [sys.executable, "-m", "bandit", "-f", "json", "-q", tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0 and not result.stdout.strip():
                return 0

            try:
                report = json.loads(result.stdout)
                return len(report.get("results", []))
            except json.JSONDecodeError:
                return 0

        except Exception:
            return 0
        finally:
            try:
                if tmp_path and os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except Exception:
                pass

    def calculate_overall_efficiency_score(
        self,
        performance_gain: Optional[float] = None,
        quality_score: Optional[float] = None,
        security_vulnerabilities: Optional[int] = None,
        semantic_equivalence: Optional[bool] = None,
        target_performance_gain: float = 0.20,
    ) -> float:
        """
        Combine the individual evaluation metrics into a single 0..1 score.

        Each available metric contributes a weighted component; weights of
        missing metrics are redistributed among the available ones:

        - performance: gain normalized against the 20% research target
        - quality: AST-based quality score (already 0..1)
        - security: 1 / (1 + vulnerabilities found by Bandit)
        - semantics: 1.0 when equivalence is proven, 0.0 when it is broken
        """
        components: list[tuple[str, float, float]] = []

        if performance_gain is not None:
            components.append(("performance", 0.35, max(0.0, min(performance_gain / target_performance_gain, 1.0))))

        if quality_score is not None:
            components.append(("quality", 0.25, max(0.0, min(quality_score, 1.0))))

        if security_vulnerabilities is not None:
            components.append(("security", 0.25, 1.0 / (1.0 + max(0, security_vulnerabilities))))

        if semantic_equivalence is not None:
            components.append(("semantics", 0.15, 1.0 if semantic_equivalence else 0.0))

        if not components:
            return 0.0

        total_weight = sum(weight for _, weight, _ in components)
        score = sum(weight * value for _, weight, value in components) / total_weight
        return max(0.0, min(score, 1.0))

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

        function_name = task.target_symbol or self._detect_function_name(task.current_code)

        performance_gain = None
        semantic_equivalence = None
        benchmark_pass_rate = None
        semantic_test_results = None
        performance_details: dict[str, Optional[float]] = {}

        if function_name:
            try:
                performance_details = self.compare_performance_detailed(
                    task.current_code,
                    proposal.new_code,
                    function_name,
                    args_template=args_template,
                    kwargs_template=kwargs_template,
                )
                performance_gain = performance_details["gain"]
            except Exception:
                performance_gain = None
                performance_details = {}

        effective_suite: list[str] = []

        if test_suite:
            effective_suite.extend(test_suite)

        if test_code and not effective_suite:
            effective_suite.append(test_code)

        if effective_suite and function_name:
            equivalence_report = self.check_equivalence_with_confidence(
                task.current_code,
                proposal.new_code,
                effective_suite,
            )
            semantic_test_results = equivalence_report.to_dict()
            semantic_equivalence = equivalence_report.equivalent
            benchmark_pass_rate = float(equivalence_report.pass_rate_new)

        safety_score = self.calculate_safety_score(safety_result, execution_result)
        quality_score = self.calculate_quality_score(proposal.new_code)
        security_vulnerabilities = self.count_security_vulnerabilities(proposal.new_code)
        overall_efficiency_score = self.calculate_overall_efficiency_score(
            performance_gain=performance_gain,
            quality_score=quality_score,
            security_vulnerabilities=security_vulnerabilities,
            semantic_equivalence=semantic_equivalence,
        )

        # Экономия в $: только при заданных тарифах и измеренных временах
        old_cost_usd: Optional[float] = None
        new_cost_usd: Optional[float] = None
        cost_savings_usd: Optional[float] = None
        cost_reduction: Optional[float] = None
        savings: Optional[SavingsResult] = None

        if self.cost_model is not None and performance_details.get("old_time_sec") is not None:
            savings = self.cost_model.compare(
                self.cost_model.compute_cost(performance_details["old_time_sec"]),
                self.cost_model.compute_cost(performance_details["new_time_sec"]),
            )
            old_cost_usd = savings.old_unit_cost_usd
            new_cost_usd = savings.new_unit_cost_usd
            cost_savings_usd = savings.savings_usd
            cost_reduction = savings.savings_ratio

        approved = (
            safety_result.approved
            and execution_result.success
            and (semantic_equivalence is None or semantic_equivalence)
        )

        details = {
            "execution_duration": execution_result.duration_sec,
            "model_name": proposal.model_name,
        }

        if savings is not None:
            details["savings_usd_per_1k_runs"] = savings.savings_per(1000)

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
            old_cost_usd=old_cost_usd,
            new_cost_usd=new_cost_usd,
            cost_savings_usd=cost_savings_usd,
            cost_reduction=cost_reduction,
            details=details,
        )

    def _measure_time(
        self,
        code: str,
        function_name: str,
        args: tuple = (),
        kwargs: dict = None,
        timeout: float = 10.0,
    ) -> float:
        """Измеряет время выполнения функции в отдельном процессе с жёстким таймаутом.

        Процесс запускается напрямую через multiprocessing (не через пул):
        по истечении таймаута он принудительно завершается, поэтому
        зависший код (бесконечный цикл) не блокирует аудитора.
        """
        kwargs = kwargs or {}

        perf_repeat = self.performance_repeat
        perf_iterations = self.performance_iterations

        result_queue: multiprocessing.Queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=_benchmark_process,
            args=(
                code,
                function_name,
                tuple(args),
                kwargs,
                perf_repeat,
                perf_iterations,
                result_queue,
            ),
        )
        process.start()
        process.join(timeout)

        if process.is_alive():
            # Зависший воркер: убиваем, не ждём завершения
            process.terminate()
            process.join(1.0)
            if process.is_alive():
                process.kill()
                process.join(1.0)
            raise TimeoutError(
                f"Benchmark for '{function_name}' timed out after {timeout}s "
                f"(possible infinite loop)"
            )

        try:
            status, payload = result_queue.get_nowait()
        except Exception:
            raise RuntimeError(
                f"Benchmark for '{function_name}' crashed without a result "
                f"(exit code {process.exitcode})"
            )

        if status == "error":
            raise RuntimeError(f"Benchmark failed: {payload}")

        return payload

    def _run_tests(self, code: str, test_code: str) -> bool:
        namespace: dict[str, Any] = {}
        try:
            exec(code, namespace)
            exec(test_code, namespace)
            return True
        except Exception:
            return False

    @staticmethod
    def _detect_function_name(code: str) -> Optional[str]:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return None

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node.name

        return None

    @staticmethod
    def _count_nested_loops(tree: ast.AST) -> int:
        max_depth = 0

        def visit(node: ast.AST, depth: int) -> None:
            nonlocal max_depth

            if isinstance(node, (ast.For, ast.While)):
                current_depth = depth + 1
                max_depth = max(max_depth, current_depth)
                for child in ast.iter_child_nodes(node):
                    visit(child, current_depth)
            else:
                for child in ast.iter_child_nodes(node):
                    visit(child, depth)

        visit(tree, 0)
        return max_depth
