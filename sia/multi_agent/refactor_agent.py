from __future__ import annotations

import time
from typing import Any

from ..models import Task
from .base_agent import AgentResult, BaseAgent


class RefactorAgent(BaseAgent):
    """Агент рефакторинга кода для улучшения читаемости и структуры."""

    def run(self, task: Task, context: dict[str, Any]) -> AgentResult:
        start_time = time.time()

        try:
            code = context.get("new_code", "")

            if not code:
                return AgentResult(
                    agent_name=self.name,
                    success=False,
                    error="No code provided for refactoring",
                    duration_sec=time.time() - start_time,
                )

            prompt = self._build_prompt(task, code)
            raw_response = self._call_llm(prompt)
            parsed = self._parse_json_response(raw_response)

            refactored_code = parsed.get("refactored_code", "")
            changes = parsed.get("changes", [])
            rationale = parsed.get("rationale", "")

            if not refactored_code:
                # Если рефакторинг не нужен, возвращаем исходный код
                refactored_code = code
                rationale = "No refactoring needed"

            return AgentResult(
                agent_name=self.name,
                success=True,
                output={
                    "refactored_code": refactored_code,
                    "changes": changes,
                    "rationale": rationale,
                    "change_count": len(changes),
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
            f"Code to refactor:\n```python\n{code}\n```\n\n"
            "Refactor the code above to improve:\n"
            "- Readability and clarity\n"
            "- Code organization\n"
            "- Naming conventions\n"
            "- Removal of unnecessary complexity\n\n"
            "IMPORTANT: Do NOT change the functionality or performance characteristics.\n"
            "The refactored code must be semantically equivalent to the original.\n\n"
            "Return a JSON object with fields:\n"
            '- "refactored_code": the improved Python code (string)\n'
            '- "changes": array of strings describing what was changed\n'
            '- "rationale": explanation of improvements (string)\n\n'
            "If the code is already well-structured, return the original code with an empty changes array.\n"
            "Return ONLY valid JSON, no markdown fences.\n"
        )

    def _system_prompt(self) -> str:
        return (
            "You are a senior Python code refactoring specialist. "
            "Your task is to improve code readability and structure without changing functionality. "
            "Focus on clarity, maintainability, and following Python best practices. "
            "Always respond with valid JSON only."
        )
