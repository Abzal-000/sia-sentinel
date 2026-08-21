from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from sia.models import Task
from sia.multi_agent import MultiAgentOrchestrator
from sia.multi_agent.base_agent import AgentResult


class MultiAgentOrchestratorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.task = Task(
            description="Optimize function",
            target_path="src/test.py",
            current_code="def add(a, b):\n    return a + b\n",
            target_symbol="add",
            allowed_paths=("src/test.py",),
        )

        self.trust_manager = MagicMock()
        self.trust_manager.can_modify.return_value = MagicMock(
            allowed=True,
            current_level=MagicMock(name="NOVICE"),
            reason=None,
        )
        self.trust_manager.level = MagicMock(name="NOVICE")

        self.safety_guard = MagicMock()
        self.safety_guard.check.return_value = MagicMock(
            approved=True,
            violations=[],
            warnings=[],
        )

        self.generator_agent = MagicMock()
        self.generator_agent.run.return_value = AgentResult(
            agent_name="generator",
            success=True,
            output={
                "new_code": "def add(a, b):\n    return b + a\n",
                "rationale": "Optimized",
                "model_name": "test-model",
            },
            duration_sec=1.0,
        )

        self.security_agent = MagicMock()
        self.security_agent.run.return_value = AgentResult(
            agent_name="security",
            success=True,
            output={
                "approved": True,
                "vulnerabilities": [],
                "warnings": [],
                "rationale": "Safe",
            },
            duration_sec=0.5,
        )

        self.test_agent = MagicMock()
        self.test_agent.run.return_value = AgentResult(
            agent_name="test",
            success=True,
            output={
                "tests": ["assert add(1, 2) == 3"],
                "test_count": 1,
            },
            duration_sec=0.5,
        )

        self.refactor_agent = MagicMock()
        self.refactor_agent.run.return_value = AgentResult(
            agent_name="refactor",
            success=True,
            output={
                "refactored_code": "def add(a, b):\n    return b + a\n",
                "changes": [],
                "rationale": "No changes needed",
            },
            duration_sec=0.3,
        )

        self.sandbox_executor = MagicMock()
        self.sandbox_executor.run.return_value = MagicMock(
            success=True,
            stdout="TESTS_PASSED",
            stderr="",
            exit_code=0,
            duration_sec=0.5,
            timed_out=False,
            error=None,
        )

        self.evaluation_engine = MagicMock()
        self.evaluation_engine.evaluate.return_value = MagicMock(
            task_id=self.task.task_id,
            approved=True,
            performance_gain=0.1,
            safety_score=1.0,
            semantic_equivalence=True,
            quality_score=1.0,
            security_vulnerabilities=0,
        )

        self.event_logger = MagicMock()

        self.orchestrator = MultiAgentOrchestrator(
            trust_manager=self.trust_manager,
            safety_guard=self.safety_guard,
            generator_agent=self.generator_agent,
            security_agent=self.security_agent,
            test_agent=self.test_agent,
            refactor_agent=self.refactor_agent,
            sandbox_executor=self.sandbox_executor,
            evaluation_engine=self.evaluation_engine,
            event_logger=self.event_logger,
        )

    def test_happy_path(self) -> None:
        result = self.orchestrator.run_task(self.task)

        self.assertTrue(result.approved)
        self.generator_agent.run.assert_called_once()
        self.security_agent.run.assert_called_once()
        self.test_agent.run.assert_called_once()
        self.refactor_agent.run.assert_called_once()

    def test_trust_denied(self) -> None:
        self.trust_manager.can_modify.return_value = MagicMock(
            allowed=False,
            current_level=MagicMock(name="NOVICE"),
            reason="Trust denied",
        )

        result = self.orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(result.details["stage"], "trust")

    def test_generator_fails(self) -> None:
        self.generator_agent.run.return_value = AgentResult(
            agent_name="generator",
            success=False,
            error="LLM error",
        )

        result = self.orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(result.details["stage"], "generator_agent")

    def test_security_rejects(self) -> None:
        self.security_agent.run.return_value = AgentResult(
            agent_name="security",
            success=True,
            output={
                "approved": False,
                "vulnerabilities": ["Dangerous operation"],
                "warnings": [],
            },
        )

        result = self.orchestrator.run_task(self.task)

        self.assertFalse(result.approved)
        self.assertEqual(result.details["stage"], "security_agent")
        self.trust_manager.record_failure.assert_called_once()


if __name__ == "__main__":
    unittest.main()
