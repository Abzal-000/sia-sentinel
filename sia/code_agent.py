from __future__ import annotations

import json
import os
import re
from typing import Optional

from .models import ChangeProposal, Task


DEFAULT_SYSTEM_PROMPT = """\
You are a senior Python engineer working inside a self-improving agent.

Your task:
- You receive a Python function or class and a description of the optimization goal.
- You must return an improved version of the code.
- You must preserve the public API (function name, signature, class name).
- You must preserve semantic equivalence: the optimized code must produce the same outputs for the same inputs.
- You must not import or use privileged, filesystem, network, or process modules.
- You must not use eval, exec, open, getattr, setattr, __import__, or dangerous dunder attributes.

Output format (strict):
You must respond with a SINGLE JSON object, and nothing else. No prose, no markdown fences, no explanations outside JSON.

The JSON object must have exactly these two keys:
{
  "new_code": "<full replacement code as a string>",
  "rationale": "<short explanation of what you changed and why>"
}
"""


class CodeAgentError(RuntimeError):
    pass


class CodeAgent:
    def __init__(
        self,
        model_name: str = "thinkingmachines/inkling",
        api_key: Optional[str] = None,
        base_url: str = "https://integrate.api.nvidia.com/v1",
        temperature: float = 0.2,
        max_tokens: int = 4096,
        request_timeout: float = 180.0,
    ) -> None:
        self.model_name = model_name
        self.base_url = base_url
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.request_timeout = request_timeout
        self._api_key = api_key

    @property
    def api_key(self) -> Optional[str]:
        if self._api_key:
            return self._api_key
        return os.environ.get("NVIDIA_API_KEY")

    def generate_change(self, task: Task) -> ChangeProposal:
        if not self.api_key:
            raise CodeAgentError(
                "NVIDIA_API_KEY is not configured. "
                "Set it in Colab Secrets or as an environment variable."
            )

        user_prompt = self._build_user_prompt(task)
        raw_response = self._call_llm(user_prompt)
        parsed = self._parse_response(raw_response)

        new_code = parsed.get("new_code")
        rationale = parsed.get("rationale", "")

        if not isinstance(new_code, str) or not new_code.strip():
            raise CodeAgentError(
                f"LLM response did not contain a valid 'new_code' field. Raw: {raw_response!r}"
            )

        return ChangeProposal(
            task_id=task.task_id,
            new_code=new_code,
            rationale=str(rationale) if rationale else "",
            model_name=self.model_name,
            raw_response={"text": raw_response},
        )

    @staticmethod
    def _build_user_prompt(task: Task) -> str:
        parts = [
            "Task description:",
            task.description,
            "",
            "Target path:",
            task.target_path,
            "",
        ]

        if task.target_symbol:
            parts.extend(
                [
                    "Target symbol to optimize:",
                    task.target_symbol,
                    "",
                ]
            )

        parts.extend(
            [
                "Current code:",
                "```python",
                task.current_code,
                "```",
                "",
                "Return only the JSON object described in the system prompt.",
            ]
        )

        return "\n".join(parts)

    def _call_llm(self, user_prompt: str, max_retries: int = 5) -> str:
        """Вызывает LLM с retry-логикой для transient errors (404, 429, 5xx, timeout)."""
        import time
        from openai import OpenAI, APITimeoutError, RateLimitError, APIStatusError

        client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self.request_timeout,
        )

        last_exception: Optional[Exception] = None

        for attempt in range(1, max_retries + 1):
            try:
                response = client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    stream=False,
                )

                message = response.choices[0].message.content or ""
                return message.strip()

            except APITimeoutError as exc:
                last_exception = exc
                # Всегда ретраим таймауты
            except RateLimitError as exc:
                last_exception = exc
                # 429 — всегда ретраим
            except APIStatusError as exc:
                status = exc.status_code
                last_exception = exc
                if status == 404 or 500 <= status < 600:
                    # 404 (модель недоступна) и 5xx (серверные ошибки) — ретраим
                    pass
                else:
                    # Другие 4xx (400, 401, 403) — не ретраим, это ошибка клиента
                    raise
            except Exception as exc:
                last_exception = exc
                raise

            # Экспоненциальная задержка: 2s, 4s, 8s, 16s, 32s
            wait_time = 2 ** attempt
            print(f"[CodeAgent] Attempt {attempt}/{max_retries} failed ({type(last_exception).__name__}). Retrying in {wait_time}s...")
            time.sleep(wait_time)

        raise RuntimeError(
            f"LLM call failed after {max_retries} attempts. Last error: {last_exception}"
        )

    @staticmethod
    def _parse_response(raw: str) -> dict:
        text = raw.strip()

        # убираем возможные markdown-ограждения ```json ... ```
        fence_match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if fence_match:
            text = fence_match.group(1).strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CodeAgentError(
                f"Failed to parse LLM response as JSON: {exc}. Raw: {raw!r}"
            ) from exc

        if not isinstance(data, dict):
            raise CodeAgentError(
                f"LLM response JSON is not an object: {type(data).__name__}"
            )

        return data
