from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from sia.code_agent import CodeAgent, CodeAgentError
from sia.models import Task


class CodeAgentTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.task = Task(
            description="Оптимизировать функцию вычисления чисел Фибоначчи",
            target_path="src/fib.py",
            current_code="def fib(n):\n    if n < 2:\n        return n\n    return fib(n-1) + fib(n-2)\n",
            target_symbol="fib",
            allowed_paths=("src/fib.py",),
        )

    def test_missing_api_key_raises_error(self) -> None:
        agent = CodeAgent(api_key=None)

        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(CodeAgentError):
                agent.generate_change(self.task)

    def _make_agent_with_fake_llm(self, fake_response: str) -> CodeAgent:
        agent = CodeAgent(api_key="fake-key-for-tests")

        def fake_call_llm(self_, user_prompt: str) -> str:
            return fake_response

        # подменяем метод на уровне экземпляра
        import types
        agent._call_llm = types.MethodType(fake_call_llm, agent)
        return agent

    def test_valid_json_response_returns_change_proposal(self) -> None:
        payload = {
            "new_code": "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n",
            "rationale": "Итеративная версия вместо рекурсии.",
        }

        agent = self._make_agent_with_fake_llm(json.dumps(payload))
        proposal = agent.generate_change(self.task)

        self.assertEqual(proposal.task_id, self.task.task_id)
        self.assertEqual(proposal.model_name, agent.model_name)
        self.assertIn("def fib", proposal.new_code)
        self.assertIn("Итеративная", proposal.rationale)

    def test_markdown_fenced_json_is_parsed(self) -> None:
        payload = {
            "new_code": "def fib(n):\n    return n\n",
            "rationale": "mock",
        }
        fenced = "```json\n" + json.dumps(payload) + "\n```"

        agent = self._make_agent_with_fake_llm(fenced)
        proposal = agent.generate_change(self.task)

        self.assertIn("def fib", proposal.new_code)

    def test_invalid_json_raises_error(self) -> None:
        agent = self._make_agent_with_fake_llm("this is not json")

        with self.assertRaises(CodeAgentError):
            agent.generate_change(self.task)

    def test_missing_new_code_raises_error(self) -> None:
        payload = {"rationale": "no code"}
        agent = self._make_agent_with_fake_llm(json.dumps(payload))

        with self.assertRaises(CodeAgentError):
            agent.generate_change(self.task)

    def test_empty_new_code_raises_error(self) -> None:
        payload = {"new_code": "   ", "rationale": "empty"}
        agent = self._make_agent_with_fake_llm(json.dumps(payload))

        with self.assertRaises(CodeAgentError):
            agent.generate_change(self.task)

    def test_json_array_raises_error(self) -> None:
        agent = self._make_agent_with_fake_llm("[1, 2, 3]")

        with self.assertRaises(CodeAgentError):
            agent.generate_change(self.task)
