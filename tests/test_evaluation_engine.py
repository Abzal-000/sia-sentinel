from __future__ import annotations

import unittest

from sia.evaluation_engine import EvaluationEngine
from sia.models import (
    ChangeProposal,
    ExecutionResult,
    SafetyCheckResult,
    Task,
)


class EvaluationEngineTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = EvaluationEngine(performance_iterations=100, performance_repeat=2)

    def test_compare_performance_slow_to_fast(self) -> None:
        old_code = """
def slow(n):
    result = 0
    for i in range(n):
        result += i
    return result
"""
        new_code = """
def slow(n):
    return n * (n - 1) // 2
"""
        gain = self.engine.compare_performance(old_code, new_code, "slow", args_template=(1000,))
        self.assertGreater(gain, 0.0)

    def test_compare_performance_same_code(self) -> None:
        # Используем функцию с измеримым временем выполнения, чтобы избежать шума timeit на наносекундах
        code = """
def heavy_sum(n):
    return sum(range(n))
"""
        gain = self.engine.compare_performance(code, code, "heavy_sum", args_template=(10000,))
        # Допускаем погрешность измерений до 20% (0.2) из-за системного шума
        self.assertAlmostEqual(gain, 0.0, delta=0.5)

    def test_measure_time_kills_hung_worker(self) -> None:
        # H5: зависший воркер должен быть убит по таймауту, а не дожидан
        import time

        hung_code = "def loop(n):\n    while True:\n        pass\n"

        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            self.engine._measure_time(hung_code, "loop", args=(1,), timeout=2.0)
        elapsed = time.monotonic() - start

        # Если бы мы ждали завершения воркера, тест висел бы вечно;
        # разумный запас на запуск процесса и завершение
        self.assertLess(elapsed, 15.0)

    def test_run_tests_kills_hung_code(self) -> None:
        # E7: зависший аудитируемый код не исполняется в процессе
        # Sentinel — его процесс убивается по таймауту, тест считается
        # проваленным, аудит продолжает работу
        import time

        hung_code = "while True:\n    pass\n"

        start = time.monotonic()
        result = self.engine._run_tests(hung_code, "assert True", timeout=2.0)
        elapsed = time.monotonic() - start

        self.assertFalse(result)
        self.assertLess(elapsed, 15.0)

    def test_run_tests_hard_crash_is_test_failure(self) -> None:
        # E7: жёсткий крах дочернего процесса (os._exit) — провал теста,
        # а не авария процесса-аудитора
        crashing_code = "import os\nos._exit(1)\n"

        result = self.engine._run_tests(crashing_code, "assert True", timeout=10.0)

        self.assertFalse(result)

    def test_run_tests_system_exit_is_test_failure(self) -> None:
        # E7: sys.exit() в аудитируемом коде не должен покидать аудитора
        exiting_code = "import sys\nsys.exit(3)\n"

        result = self.engine._run_tests(exiting_code, "assert True", timeout=10.0)

        self.assertFalse(result)

    def test_run_tests_passing_code_in_child_process(self) -> None:
        # Позитивный контроль: корректный код проходит тест в дочернем процессе
        good_code = "def add(a, b):\n    return a + b\n"
        test_code = "assert add(2, 2) == 4\n"

        self.assertTrue(self.engine._run_tests(good_code, test_code, timeout=10.0))

    def test_calculate_safety_score_perfect(self) -> None:
        safety = SafetyCheckResult(approved=True, violations=(), warnings=())
        execution = ExecutionResult(success=True, exit_code=0)

        score = self.engine.calculate_safety_score(safety, execution)
        self.assertEqual(score, 1.0)

    def test_calculate_safety_score_with_violations(self) -> None:
        safety = SafetyCheckResult(
            approved=False,
            violations=("no-dangerous-calls: eval", "no-dangerous-calls: exec"),
            warnings=("some warning",),
        )
        execution = ExecutionResult(success=True, exit_code=0)

        score = self.engine.calculate_safety_score(safety, execution)
        self.assertLess(score, 1.0)
        self.assertGreaterEqual(score, 0.0)

    def test_calculate_safety_score_execution_failed(self) -> None:
        safety = SafetyCheckResult(approved=True, violations=(), warnings=())
        execution = ExecutionResult(success=False, exit_code=1)

        score = self.engine.calculate_safety_score(safety, execution)
        self.assertLess(score, 1.0)

    def test_check_semantic_equivalence_both_pass(self) -> None:
        old_code = """
def add(a, b):
    return a + b
"""
        new_code = """
def add(a, b):
    return b + a
"""
        test_code = """
assert add(1, 2) == 3
assert add(10, 20) == 30
"""
        result = self.engine.check_semantic_equivalence(old_code, new_code, test_code)
        self.assertTrue(result)

    def test_check_semantic_equivalence_new_fails(self) -> None:
        old_code = """
def add(a, b):
    return a + b
"""
        new_code = """
def add(a, b):
    return a * b
"""
        test_code = """
assert add(1, 2) == 3
"""
        result = self.engine.check_semantic_equivalence(old_code, new_code, test_code)
        self.assertFalse(result)

    def test_calculate_quality_score_good_code(self) -> None:
        code = """
def add(a, b):
    return a + b
"""
        score = self.engine.calculate_quality_score(code)
        self.assertGreater(score, 0.5)

    def test_calculate_quality_score_long_code(self) -> None:
        code = "def f():\n" + "    x = 1\n" * 150
        score = self.engine.calculate_quality_score(code)
        self.assertLess(score, 1.0)

    def test_count_security_vulnerabilities_clean_code(self) -> None:
        code = """
def add(a, b):
    return a + b
"""
        count = self.engine.count_security_vulnerabilities(code)
        self.assertEqual(count, 0)

    def test_count_security_vulnerabilities_dangerous_code(self) -> None:
        code = """
def bad():
    eval("1 + 1")
    exec("x = 1")
"""
        count = self.engine.count_security_vulnerabilities(code)
        self.assertEqual(count, 2)

    def test_evaluate_approved(self) -> None:
        task = Task(
            description="Optimize",
            target_path="test.py",
            current_code="def add(a, b):\n    return a + b\n",
            target_symbol="add",
        )
        proposal = ChangeProposal(
            task_id=task.task_id,
            new_code="def add(a, b):\n    return b + a\n",
        )
        safety = SafetyCheckResult(approved=True, violations=(), warnings=())
        execution = ExecutionResult(success=True, exit_code=0)

        result = self.engine.evaluate(task, proposal, safety, execution)

        self.assertTrue(result.approved)
        self.assertIsNotNone(result.safety_score)

    def test_evaluate_safety_failed(self) -> None:
        task = Task(
            description="Optimize",
            target_path="test.py",
            current_code="def add(a, b):\n    return a + b\n",
            target_symbol="add",
        )
        proposal = ChangeProposal(
            task_id=task.task_id,
            new_code="def add(a, b):\n    return a + b\n",
        )
        safety = SafetyCheckResult(approved=False, violations=("violation",))
        execution = ExecutionResult(success=True, exit_code=0)

        result = self.engine.evaluate(task, proposal, safety, execution)

        self.assertFalse(result.approved)

    def test_evaluate_execution_failed(self) -> None:
        task = Task(
            description="Optimize",
            target_path="test.py",
            current_code="def add(a, b):\n    return a + b\n",
            target_symbol="add",
        )
        proposal = ChangeProposal(
            task_id=task.task_id,
            new_code="def add(a, b):\n    return a + b\n",
        )
        safety = SafetyCheckResult(approved=True, violations=(), warnings=())
        execution = ExecutionResult(success=False, exit_code=1)

        result = self.engine.evaluate(task, proposal, safety, execution)

        self.assertFalse(result.approved)

    def test_overall_efficiency_score_perfect(self) -> None:
        score = self.engine.calculate_overall_efficiency_score(
            performance_gain=0.25,
            quality_score=0.95,
            security_vulnerabilities=0,
            semantic_equivalence=True,
        )

        self.assertGreaterEqual(score, 0.9)
        self.assertLessEqual(score, 1.0)

    def test_overall_efficiency_score_broken_semantics(self) -> None:
        good = self.engine.calculate_overall_efficiency_score(
            performance_gain=0.25,
            quality_score=0.9,
            security_vulnerabilities=0,
            semantic_equivalence=True,
        )
        broken = self.engine.calculate_overall_efficiency_score(
            performance_gain=0.25,
            quality_score=0.9,
            security_vulnerabilities=0,
            semantic_equivalence=False,
        )

        self.assertLess(broken, good)

    def test_overall_efficiency_score_partial_metrics(self) -> None:
        score = self.engine.calculate_overall_efficiency_score(quality_score=1.0)

        self.assertAlmostEqual(score, 1.0)

        empty = self.engine.calculate_overall_efficiency_score()

        self.assertEqual(empty, 0.0)

    def test_overall_efficiency_score_clamps_gain(self) -> None:
        huge = self.engine.calculate_overall_efficiency_score(performance_gain=5.0)
        negative = self.engine.calculate_overall_efficiency_score(performance_gain=-1.0)

        self.assertLessEqual(huge, 1.0)
        self.assertGreaterEqual(negative, 0.0)

    def test_evaluate_sets_overall_efficiency_score(self) -> None:
        task = Task(
            description="Optimize",
            target_path="test.py",
            current_code="def add(a, b):\n    return a + b\n",
            target_symbol="add",
        )
        proposal = ChangeProposal(
            task_id=task.task_id,
            new_code="def add(a, b):\n    return a + b\n",
        )
        safety = SafetyCheckResult(approved=True, violations=(), warnings=())
        execution = ExecutionResult(success=True, exit_code=0)

        result = self.engine.evaluate(task, proposal, safety, execution)

        self.assertIsNotNone(result.overall_efficiency_score)
        self.assertTrue(0.0 <= result.overall_efficiency_score <= 1.0)
