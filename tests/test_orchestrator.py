from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Optional

from sia.code_agent import CodeAgentError
from sia.event_logger import EventLogger
from sia.models import (
    ChangeProposal,
    EvaluationResult,
    ExecutionResult,
    SafetyCheckResult,
    Task,
    TrustDecision,
    TrustLevel,
)
from sia.orchestrator import Orchestrator


class FakeTrustManager:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.successes: list[str] = []
        self.failures: list[tuple[str, str]] = []
        self._level = TrustLevel.NOVICE

    @property
    def level(self) -> TrustLevel:
        return self._level

    def can_modify(self, task: Task) -> TrustDecision:
        return TrustDecision(
            allowed=self.allowed,
            current_level=self._level,
            reason="fake trust decision",
        )

    def record_success(self, task: Task) -> None:
        self.successes.append(task.task_id)

    def record_failure(self, task: Task, reason: str) -> None:
        self.failures.append((task.task_id, reason))


class FakeGuard:
    def __init__(self, approved: bool = True, violations: tuple[str, ...] = ()) -> None:
        self.approved = approved
        self.violations = violations
        self.calls: list[str] = []

    def check(self, code: str) -> SafetyCheckResult:
        self.calls.append(code)
        return SafetyCheckResult(
            approved=self.approved,
            violations=tuple(self.violations),
        )


class FakeAgent:
    def __init__(
        self,
        error: Optional[Exception] = None,
        new_code: str = "def foo():\n    return 1\n",
    ) -> None:
        self.error = error
        self.new_code = new_code
        self.calls: list[str] = []

    def generate_change(self, task: Task) -> ChangeProposal:
        self.calls.append(task.task_id)

        if self.error is not None:
            raise self.error

        return ChangeProposal(
            task_id=task.task_id,
            new_code=self.new_code,
            rationale="fake rationale",
            model_name="fake-model",
        )


class FakeSandbox:
    def __init__(
        self,
        success: bool = True,
        error: Optional[str] = None,
        timed_out: bool = False,
    ) -> None:
        self.success = success
        self.error = error
        self.timed_out = timed_out
        self.calls: list[str] = []

    def run(self, code: str, test_code: Optional[str] = None) -> ExecutionResult:
        self.calls.append(code)

        return ExecutionResult(
            success=self.success,
            stdout="",
            stderr="",
            exit_code=0 if self.success else 1,
            error=self.error,
            timed_out=self.timed_out,
        )


class FakeEvaluator:
    def __init__(self, approved: bool = True) -> None:
        self.approved = approved
        self.calls: list[str] = []

    def evaluate(
        self,
        task: Task,
        proposal: ChangeProposal,
        safety_result: SafetyCheckResult,
        execution_result: ExecutionResult,
        test_code: Optional[str] = None,
        test_suite: Optional[list] = None,
        args_template: Optional[tuple] = None,
        kwargs_template: Optional[dict] = None,
    ) -> EvaluationResult:
        self.calls.append(task.task_id)

        return EvaluationResult(
            task_id=task.task_id,
            approved=self.approved,
        )


class OrchestratorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.logger = EventLogger(log_dir=self._tmp.name)

        self.task = Task(
            description="Optimize foo",
            target_path="src/foo.py",
            current_code="def foo():\n    return 1\n",
            target_symbol="foo",
            allowed_paths=("src",),
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _build_orchestrator(
        self,
        trust_manager: FakeTrustManager,
        safety_guard: FakeGuard,
        code_agent: FakeAgent,
        sandbox_executor: FakeSandbox,
        evaluation_engine: FakeEvaluator,
    ) -> Orchestrator:
        return Orchestrator(
            trust_manager=trust_manager,
            safety_guard=safety_guard,
            code_agent=code_agent,
            sandbox_executor=sandbox_executor,
            evaluation_engine=evaluation_engine,
            event_logger=self.logger,
        )

    def test_happy_path(self) -> None:
        trust = FakeTrustManager(allowed=True)
        guard = FakeGuard(approved=True)
        agent = FakeAgent()
        sandbox = FakeSandbox(success=True)
        evaluator = FakeEvaluator(approved=True)

        orchestrator = self._build_orchestrator(
            trust_manager=trust,
            safety_guard=guard,
            code_agent=agent,
            sandbox_executor=sandbox,
            evaluation_engine=evaluator,
        )

        result = orchestrator.run_task(self.task)

        self.assertTrue(result.approved)
        self.assertEqual(trust.successes, [self.task.task_id])
        self.assertEqual(trust.failures, [])
        self.assertEqual(agent.calls, [self.task.task_id])
        self.assertEqual(guard.calls, [agent.new_code])
        self.assertEqual(sandbox.calls, [agent.new_code])
        self.assertEqual(evaluator.calls, [self.task.task_id])

        events_path = Path(self._tmp.name) / "events.jsonl"
        self.assertTrue(events_path.exists())
        self.assertGreater(len(events_path.read_text().splitlines()), 0)

    def test_trust_denied(self) -> None:
        trust = FakeTrustManager(allowed=False)
        guard = FakeGuard(approved=True)
        agent = FakeAgent()
        sandbox = FakeSandbox(success=True)
        evaluator = FakeEvaluator(approved=True)

        orchestrator = self._build_orchestrator(
            trust_manager=trust,
            safety_guard=guard,
            code_agent=agent,
            sandbox_executor=sandbox,
            evaluation_engine=evaluator,
        )

        result = orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(result.details.get("stage"), "trust")
        self.assertEqual(agent.calls, [])
        self.assertEqual(sandbox.calls, [])
        self.assertEqual(evaluator.calls, [])
        self.assertEqual(trust.successes, [])
        self.assertEqual(trust.failures, [])

    def test_safety_violation_blocks_sandbox(self) -> None:
        trust = FakeTrustManager(allowed=True)
        guard = FakeGuard(approved=False, violations=("bad call",))
        agent = FakeAgent()
        sandbox = FakeSandbox(success=True)
        evaluator = FakeEvaluator(approved=True)

        orchestrator = self._build_orchestrator(
            trust_manager=trust,
            safety_guard=guard,
            code_agent=agent,
            sandbox_executor=sandbox,
            evaluation_engine=evaluator,
        )

        result = orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(result.details.get("stage"), "safety")
        self.assertEqual(sandbox.calls, [])
        self.assertEqual(evaluator.calls, [])
        self.assertEqual(len(trust.failures), 1)
        self.assertEqual(trust.failures[0][1], "safety_violation")

    def test_sandbox_failure_blocks_evaluation(self) -> None:
        trust = FakeTrustManager(allowed=True)
        guard = FakeGuard(approved=True)
        agent = FakeAgent()
        sandbox = FakeSandbox(success=False, error="timeout")
        evaluator = FakeEvaluator(approved=True)

        orchestrator = self._build_orchestrator(
            trust_manager=trust,
            safety_guard=guard,
            code_agent=agent,
            sandbox_executor=sandbox,
            evaluation_engine=evaluator,
        )

        result = orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(result.details.get("stage"), "sandbox")
        self.assertEqual(evaluator.calls, [])
        self.assertEqual(len(trust.failures), 1)

    def test_evaluation_not_approved_records_failure(self) -> None:
        trust = FakeTrustManager(allowed=True)
        guard = FakeGuard(approved=True)
        agent = FakeAgent()
        sandbox = FakeSandbox(success=True)
        evaluator = FakeEvaluator(approved=False)

        orchestrator = self._build_orchestrator(
            trust_manager=trust,
            safety_guard=guard,
            code_agent=agent,
            sandbox_executor=sandbox,
            evaluation_engine=evaluator,
        )

        result = orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(evaluator.calls, [self.task.task_id])
        self.assertEqual(trust.successes, [])
        self.assertEqual(len(trust.failures), 1)
        self.assertEqual(trust.failures[0][1], "evaluation_not_approved")

    def test_code_agent_error_does_not_lower_trust(self) -> None:
        trust = FakeTrustManager(allowed=True)
        guard = FakeGuard(approved=True)
        agent = FakeAgent(error=CodeAgentError("API key missing"))
        sandbox = FakeSandbox(success=True)
        evaluator = FakeEvaluator(approved=True)

        orchestrator = self._build_orchestrator(
            trust_manager=trust,
            safety_guard=guard,
            code_agent=agent,
            sandbox_executor=sandbox,
            evaluation_engine=evaluator,
        )

        result = orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(result.details.get("stage"), "code_agent")
        self.assertEqual(sandbox.calls, [])
        self.assertEqual(evaluator.calls, [])
        self.assertEqual(trust.successes, [])
        self.assertEqual(trust.failures, [])
