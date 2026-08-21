from __future__ import annotations

import time
from typing import Any

from ..models import Task
from .base_agent import AgentResult, BaseAgent


class SecurityAgent(BaseAgent):
    """Агент углублённого анализа безопасности кода."""

    def run(self, task: Task, context: dict[str, Any]) -> AgentResult:
        start_time = time.time()

        try:
            code = context.get("new_code", "")

            if not code:
                return AgentResult(
                    agent_name=self.name,
                    success=False,
                    error="No code provided for security analysis",
                    duration_sec=time.time() - start_time,
                )

            prompt = self._build_prompt(task, code)
            raw_response = self._call_llm(prompt)
            parsed = self._parse_json_response(raw_response)

            approved = parsed.get("approved", False)
            vulnerabilities = parsed.get("vulnerabilities", [])
            warnings = parsed.get("warnings", [])
            rationale = parsed.get("rationale", "")

            return AgentResult(
                agent_name=self.name,
                success=True,
                output={
                    "approved": approved,
                    "vulnerabilities": vulnerabilities,
                    "warnings": warnings,
                    "rationale": rationale,
                    "vulnerability_count": len(vulnerabilities),
                    "warning_count": len(warnings),
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
            f"Code to analyze:\n```python\n{code}\n```\n\n"
            "Perform a comprehensive security analysis of the code above.\n\n"
            "Check for:\n"
            "- Dangerous imports (os, subprocess, shutil, socket, requests)\n"
            "- Code injection risks (eval, exec, compile)\n"
            "- File system access (open, pathlib)\n"
            "- Dynamic attribute access (getattr, setattr, delattr)\n"
            "- Dunder attribute access (__class__, __globals__, __subclasses__)\n"
            "- Network operations\n"
            "- Any other security vulnerabilities\n\n"
            "Return a JSON object with fields:\n"
            '- "approved": boolean (true if code is safe, false otherwise)\n'
            '- "vulnerabilities": array of strings describing critical issues\n'
            '- "warnings": array of strings describing potential concerns\n'
            '- "rationale": explanation of your decision (string)\n\n'
            "Important:\n"
            "- Be strict: any dangerous operation should result in approved=false.\n"
            "- Return ONLY valid JSON, no markdown fences.\n"
        )

    def _system_prompt(self) -> str:
        return (
            "You are a senior security engineer specializing in Python code analysis. "
            "Your task is to identify security vulnerabilities and dangerous operations in code. "
            "Be extremely strict: any code that could access the file system, execute arbitrary code, "
            "or make network requests must be rejected. Always respond with valid JSON only."
        )
