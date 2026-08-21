from __future__ import annotations

import time
from typing import Any

from ..models import Task
from .base_agent import AgentResult, BaseAgent


class GeneratorAgent(BaseAgent):
    """Агент генерации кода. Основная задача - предложить оптимизированную версию."""

    def run(self, task: Task, context: dict[str, Any]) -> AgentResult:
        start_time = time.time()

        try:
            prompt = self._build_prompt(task)
            raw_response = self._call_llm(prompt)
            parsed = self._parse_json_response(raw_response)

            new_code = parsed.get("new_code", "")
            rationale = parsed.get("rationale", "")

            if not new_code:
                return AgentResult(
                    agent_name=self.name,
                    success=False,
                    error="LLM did not return new_code",
                    duration_sec=time.time() - start_time,
                )

            return AgentResult(
                agent_name=self.name,
                success=True,
                output={
                    "new_code": new_code,
                    "rationale": rationale,
                    "model_name": self.model_name,
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

    def _build_prompt(self, task: Task) -> str:
        return (
            f"Task description:\n{task.description}\n\n"
            f"Target path:\n{task.target_path}\n\n"
            f"Current code:\n```python\n{task.current_code}\n```\n\n"
            f"Target symbol:\n{task.target_symbol or 'N/A'}\n\n"
            "Please optimize the code above. Return a JSON object with fields:\n"
            '- "new_code": the optimized Python code (string)\n'
            '- "rationale": explanation of optimizations (string)\n\n'
            "Important:\n"
            "- The optimized code must be functionally equivalent.\n"
            "- Do not add imports that are not in the original code.\n"
            "- Return ONLY valid JSON, no markdown fences.\n"
        )

    def _system_prompt(self) -> str:
        return (
            "You are a senior Python code optimization specialist. "
            "Your task is to optimize Python code for performance while maintaining "
            "exact functional equivalence with the original code. "
            "Always respond with valid JSON only."
        )
