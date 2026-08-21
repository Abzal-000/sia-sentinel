from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

from sia.code_agent import CodeAgentError
from sia.constitutional_ai_layer import ConstitutionalAILayer
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
from sia.sandbox_executor import SandboxExecutor
from sia.security_metrics import (
    SECURITY_TEST_CASES,
    calculate_security_score,
    run_security_suite,
)
from sia.trust_level_manager import TrustLevelManager


class SecurityMetricsTestCase(unittest.TestCase):
    def test_security_score_is_high(self) -> None:
        score = calculate_security_score()
        self.assertGreaterEqual(score, 0.9)

    def test_run_security_suite_all_pass(self) -> None:
        results = run_security_suite()
        for name, passed in results.items():
            self.assertTrue(passed, msg=f"Security test failed: {name}")

    def test_security_test_cases_not_empty(self) -> None:
        self.assertGreater(len(SECURITY_TEST_CASES), 0)


class TrustLevelSecurityTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self.target_path = self.workspace / "target.py"
        self.manager = TrustLevelManager(level=TrustLevel.NOVICE)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_task(
        self,
        target_path=None,
        current_code=None,
        target_symbol=None,
        allowed_paths=None,
    ) -> Task:
        if allowed_paths is None:
            allowed_paths = (str(self.workspace),)
        return Task(
            description="Security test",
            target_path=str(target_path or self.target_path),
            current_code=current_code or "def foo():\n    return 1\n",
            target_symbol=target_symbol or "foo",
            allowed_paths=tuple(allowed_paths),
        )

    def test_path_traversal_blocked(self) -> None:
        evil_path = self.workspace / ".." / "secret.py"
        task = self._make_task(target_path=evil_path)
        decision = self.manager.can_modify(task)
        self.assertFalse(decision.allowed)

    def test_comment_def_not_function(self) -> None:
        code = "# def fake(): pass\n"
        self.target_path.write_text(code, encoding="utf-8")
        task = self._make_task(current_code=code, target_symbol=None)
        decision = self.manager.can_modify(task)
        self.assertFalse(decision.allowed)

    def test_string_def_not_function(self) -> None:
        code = "x = 'def fake(): pass'\n"
        self.target_path.write_text(code, encoding="utf-8")
        task = self._make_task(current_code=code, target_symbol=None)
        decision = self.manager.can_modify(task)
        self.assertFalse(decision.allowed)

    def test_class_blocked_for_novice(self) -> None:
        code = "class Foo:\n    pass\n"
        self.target_path.write_text(code, encoding="utf-8")
        task = self._make_task(current_code=code, target_symbol="Foo")
        decision = self.manager.can_modify(task)
        self.assertFalse(decision.allowed)

    def test_empty_allowed_paths_blocked(self) -> None:
        task = self._make_task(allowed_paths=())
        decision = self.manager.can_modify(task)
        self.assertFalse(decision.allowed)


class ConstitutionalAISecurityTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.guard = ConstitutionalAILayer()

    def assert_blocked(self, code: str) -> None:
        result = self.guard.check(code)
        self.assertFalse(result.approved, msg=f"Expected block, got approved. Violations: {result.violations}")

    def assert_allowed(self, code: str) -> None:
        result = self.guard.check(code)
        self.assertTrue(result.approved, msg=f"Expected allow, got blocked. Violations: {result.violations}")

    def test_eval_blocked(self) -> None:
        self.assert_blocked("def f():\n    return eval('1')\n")

    def test_exec_blocked(self) -> None:
        self.assert_blocked("def f():\n    exec('x=1')\n")

    def test_compile_blocked(self) -> None:
        self.assert_blocked("def f():\n    compile('x=1', '<string>', 'exec')\n")

    def test_open_blocked(self) -> None:
        self.assert_blocked("def f():\n    return open('/etc/passwd').read()\n")

    def test_import_os_blocked(self) -> None:
        self.assert_blocked("import os\n")

    def test_import_subprocess_blocked(self) -> None:
        self.assert_blocked("import subprocess\n")

    def test_from_subprocess_import_blocked(self) -> None:
        self.assert_blocked("from subprocess import run\n")

    def test_import_shutil_blocked(self) -> None:
        self.assert_blocked("import shutil\n")

    def test_import_socket_blocked(self) -> None:
        self.assert_blocked("import socket\n")

    def test_import_requests_blocked(self) -> None:
        self.assert_blocked("import requests\n")

    def test_alias_import_bypass_blocked(self) -> None:
        self.assert_blocked("import shutil as s\ns.copy('a', 'b')\n")

    def test_from_import_alias_bypass_blocked(self) -> None:
        self.assert_blocked("from shutil import copy as c\nc('a', 'b')\n")

    def test_getattr_bypass_blocked(self) -> None:
        self.assert_blocked("import shutil\ngetattr(shutil, 'copy')('a', 'b')\n")

    def test_setattr_blocked(self) -> None:
        self.assert_blocked("def f(obj):\n    setattr(obj, 'x', 1)\n")

    def test_delattr_blocked(self) -> None:
        self.assert_blocked("def f(obj):\n    delattr(obj, 'x')\n")

    def test_dunder_class_blocked(self) -> None:
        self.assert_blocked("def f():\n    return ''.__class__\n")

    def test_dunder_globals_blocked(self) -> None:
        self.assert_blocked("def f():\n    return ''.__class__.__init__.__globals__\n")

    def test_dunder_subclasses_string_blocked(self) -> None:
        self.assert_blocked("def f():\n    return '__subclasses__'\n")

    def test_relative_import_blocked(self) -> None:
        self.assert_blocked("from . import utils\n")

    def test_syntax_error_blocked(self) -> None:
        self.assert_blocked("def broken(:\n    pass\n")

    def test_empty_code_blocked(self) -> None:
        self.assert_blocked("")

    def test_benign_math_allowed(self) -> None:
        self.assert_allowed("import math\n\ndef root(x):\n    return math.sqrt(x)\n")

    def test_benign_pure_function_allowed(self) -> None:
        self.assert_allowed("def add(a, b):\n    return a + b\n")

    def test_benign_dict_get_allowed(self) -> None:
        self.assert_allowed("def get(data):\n    return data.get('x', 0)\n")


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
            reason="fake",
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
        return SafetyCheckResult(approved=self.approved, violations=tuple(self.violations))


class FakeAgent:
    def __init__(self, error: Optional[Exception] = None, new_code: str = "def foo():\n    return 1\n") -> None:
        self.error = error
        self.new_code = new_code
        self.calls: list[str] = []

    def generate_change(self, task: Task) -> ChangeProposal:
        self.calls.append(task.task_id)
        if self.error:
            raise self.error
        return ChangeProposal(
            task_id=task.task_id,
            new_code=self.new_code,
            rationale="fake",
            model_name="fake-model",
        )


class FakeSandbox:
    def __init__(self, success: bool = True, timed_out: bool = False) -> None:
        self.success = success
        self.timed_out = timed_out
        self.calls: list[str] = []

    def run(self, code: str, test_code: Optional[str] = None) -> ExecutionResult:
        self.calls.append(code)
        return ExecutionResult(
            success=self.success,
            exit_code=0 if self.success else 1,
            timed_out=self.timed_out,
        )


class FakeEvaluator:
    def __init__(self, approved: bool = True) -> None:
        self.approved = approved
        self.calls: list[str] = []

    def evaluate(self, task, proposal, safety_result, execution_result, test_code=None, args_template=None, kwargs_template=None) -> EvaluationResult:
        self.calls.append(task.task_id)
        return EvaluationResult(task_id=task.task_id, approved=self.approved)


class OrchestratorSecurityTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.logger = EventLogger(log_dir=self._tmp.name)
        self.task = Task(
            description="Security test",
            target_path="src/foo.py",
            current_code="def foo():\n    return 1\n",
            target_symbol="foo",
            allowed_paths=("src",),
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _build(
        self,
        trust: FakeTrustManager,
        guard: FakeGuard,
        agent: FakeAgent,
        sandbox: FakeSandbox,
        evaluator: FakeEvaluator,
    ) -> Orchestrator:
        return Orchestrator(
            trust_manager=trust,
            safety_guard=guard,
            code_agent=agent,
            sandbox_executor=sandbox,
            evaluation_engine=evaluator,
            event_logger=self.logger,
        )

    def test_safety_violation_blocks_execution_and_lowers_trust(self) -> None:
        trust = FakeTrustManager(allowed=True)
        guard = FakeGuard(approved=False, violations=("dangerous",))
        agent = FakeAgent()
        sandbox = FakeSandbox(success=True)
        evaluator = FakeEvaluator(approved=True)

        orchestrator = self._build(trust, guard, agent, sandbox, evaluator)
        result = orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(sandbox.calls, [])
        self.assertEqual(len(trust.failures), 1)

    def test_trust_denied_blocks_agent(self) -> None:
        trust = FakeTrustManager(allowed=False)
        guard = FakeGuard(approved=True)
        agent = FakeAgent()
        sandbox = FakeSandbox(success=True)
        evaluator = FakeEvaluator(approved=True)

        orchestrator = self._build(trust, guard, agent, sandbox, evaluator)
        result = orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(agent.calls, [])
        self.assertEqual(sandbox.calls, [])

    def test_sandbox_timeout_records_failure(self) -> None:
        trust = FakeTrustManager(allowed=True)
        guard = FakeGuard(approved=True)
        agent = FakeAgent()
        sandbox = FakeSandbox(success=False, timed_out=True)
        evaluator = FakeEvaluator(approved=True)

        orchestrator = self._build(trust, guard, agent, sandbox, evaluator)
        result = orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(evaluator.calls, [])
        self.assertEqual(len(trust.failures), 1)

    def test_agent_error_does_not_lower_trust(self) -> None:
        trust = FakeTrustManager(allowed=True)
        guard = FakeGuard(approved=True)
        agent = FakeAgent(error=CodeAgentError("API error"))
        sandbox = FakeSandbox(success=True)
        evaluator = FakeEvaluator(approved=True)

        orchestrator = self._build(trust, guard, agent, sandbox, evaluator)
        result = orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(trust.failures, [])
        self.assertEqual(sandbox.calls, [])


class SandboxSecurityTestCase(unittest.TestCase):
    @patch("sia.sandbox_executor.docker")
    def test_infinite_loop_timeout_kills_container(self, mock_docker: MagicMock) -> None:
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client

        mock_container = MagicMock()
        mock_client.containers.create.return_value = mock_container

        import requests
        mock_container.wait.side_effect = requests.exceptions.ReadTimeout()
        mock_container.logs.side_effect = [b"", b""]

        executor = SandboxExecutor(timeout_sec=1)
        result = executor.run("while True:\n    pass\n")

        self.assertFalse(result.success)
        self.assertTrue(result.timed_out)
        mock_container.kill.assert_called_once()
        mock_container.remove.assert_called_once_with(force=True)

    @patch("sia.sandbox_executor.docker")
    def test_network_disabled_by_default(self, mock_docker: MagicMock) -> None:
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client

        mock_container = MagicMock()
        mock_client.containers.create.return_value = mock_container
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.side_effect = [b"", b""]

        executor = SandboxExecutor()
        executor.run("def foo():\n    return 1\n")

        create_kwargs = mock_client.containers.create.call_args.kwargs
        self.assertTrue(create_kwargs["network_disabled"])

    @patch("sia.sandbox_executor.docker")
    def test_container_removed_on_error(self, mock_docker: MagicMock) -> None:
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client

        mock_container = MagicMock()
        mock_client.containers.create.return_value = mock_container
        mock_container.start.side_effect = RuntimeError("fail")

        executor = SandboxExecutor()
        result = executor.run("def foo():\n    return 1\n")

        self.assertFalse(result.success)
        mock_container.remove.assert_called_once_with(force=True)
