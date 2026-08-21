from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from ..models import Task


@dataclass(frozen=True)
class AgentResult:
    """Результат работы агента."""

    agent_name: str
    success: bool
    output: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_sec: float = 0.0


class BaseAgent(ABC):
    """Базовый класс для всех специализированных агентов."""

    def __init__(
        self,
        name: str,
        model_name: str = "nvidia/nemotron-3-ultra-550b-a55b",
        api_key: Optional[str] = None,
        base_url: str = "https://integrate.api.nvidia.com/v1",
        request_timeout: float = 180.0,
    ) -> None:
        self.name = name
        self.model_name = model_name
        self.api_key = api_key
        self.base_url = base_url
        self.request_timeout = request_timeout

    @abstractmethod
    def run(self, task: Task, context: dict[str, Any]) -> AgentResult:
        """Основной метод агента."""
        pass

    @abstractmethod
    def _system_prompt(self) -> str:
        """Системный промпт для LLM."""
        pass

    def _call_llm(self, user_prompt: str, max_retries: int = 3) -> str:
        """Вызов LLM с автоматическим повтором при временных ошибках."""
        from openai import OpenAI

        if not self.api_key:
            raise ValueError(f"Agent '{self.name}': API key is not configured")

        client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self.request_timeout,
        )

        last_error = None
        for attempt in range(max_retries):
            try:
                response = client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": self._system_prompt()},
                        {"role": "user", "content": user_prompt},
                    ],
                )
                content = response.choices[0].message.content or ""
                return content
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt * 5
                    print(f"[{self.name}] API error (attempt {attempt + 1}/{max_retries}): {e}")
                    print(f"[{self.name}] Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    raise

        raise last_error

    @staticmethod
    def _parse_json_response(raw: str) -> dict[str, Any]:
        """Парсит JSON-ответ от LLM, обрабатывая markdown-ограждения."""
        text = raw.strip()

        if text.startswith("```"):
            lines = text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)

        return json.loads(text)
