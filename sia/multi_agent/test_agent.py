from __future__ import annotations

import time
from typing import Any

from ..models import Task
from .base_agent import AgentResult, BaseAgent


class TestAgent(BaseAgent):
    """Агент генерации тестов для проверки семантической эквивалентности."""

    def run(self, task: Task, context: dict[str, Any]) -> AgentResult:
        start_time = time.time()

        try:
            new_code = context.get("new_code", task.current_code)

            prompt = self._build_prompt(task, new_code)
            raw_response = self._call_llm(prompt)
            parsed = self._parse_json_response(raw_response)

            tests = parsed.get("tests", [])

            if not tests or not isinstance(tests, list):
                return AgentResult(
                    agent_name=self.name,
                    success=False,
                    error="LLM did not return valid tests",
                    duration_sec=time.time() - start_time,
                )

            # Фильтруем только строки
            valid_tests = [t for t in tests if isinstance(t, str) and t.strip()]

            return AgentResult(
                agent_name=self.name,
                success=True,
                output={
                    "tests": valid_tests,
                    "test_count": len(valid_tests),
                },
                duration_sec=time.time() - start_time,
            )

        except Exception as exc:
            return AgentResult(
                agent_name=self.name,
                success=False,
                error=str(exc),
                duration_sec=time.time() - start_time,
            )

    def _build_prompt(self, task: Task, code: str) -> str:
        return (
            f"Task description:\n{task.description}\n\n"
            f"Code to test:\n```python\n{code}\n```\n\n"
            f"Target function:\n{task.target_symbol or 'N/A'}\n\n"
            "Generate comprehensive unit tests for the code above.\n"
            "Focus on normal cases, edge cases, and boundary values.\n\n"
            "Return a JSON object with field:\n"
            '- "tests": an array of strings, each is a Python assert statement\n\n'
            'Example: {"tests": ["assert func(1) == 1", "assert func(0) == 0"]}\n\n'
            "Important:\n"
            "- Each test must be a valid Python assert statement.\n"
            "- Call the function directly, no unittest framework.\n"
            "- Return ONLY valid JSON, no markdown fences.\n"
        )

    def _system_prompt(self) -> str:
        return (
            "You are an expert Python test engineer. "
            "Your task is to generate comprehensive unit tests for Python functions. "
            "Focus on edge cases, boundary conditions, and typical use cases. "
            "Always respond with valid JSON only."
        )
