from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Optional

from .models import Task, TrustDecision, TrustLevel


class TrustLevelManager:
    LEVEL_TARGET_TYPES = {
        TrustLevel.NOVICE: {"function"},
        TrustLevel.INTERN: {"function"},
        TrustLevel.JUNIOR: {"function", "class"},
        TrustLevel.MID: {"function", "class"},
        TrustLevel.SENIOR: {"function", "class"},
    }

    def __init__(
        self,
        level: TrustLevel = TrustLevel.NOVICE,
        promotion_threshold: int = 3,
        demotion_threshold: int = 2,
        state_file: Optional[str] = None,
    ) -> None:
        self._level = level
        self._success_streak = 0
        self._failure_streak = 0
        self._last_failure_reason: Optional[str] = None
        self.promotion_threshold = promotion_threshold
        self.demotion_threshold = demotion_threshold

        # Файл для персистентного хранения состояния
        self._state_file = Path(state_file) if state_file else None

        # Если state_file указан — загружаем состояние
        if self._state_file is not None:
            self._load_state()

    def _load_state(self) -> None:
        """Загружает состояние TrustLevelManager из файла."""
        if self._state_file is None or not self._state_file.exists():
            return

        try:
            with open(self._state_file, "r", encoding="utf-8") as f:
                state = json.load(f)

            self._level = TrustLevel(state.get("level", TrustLevel.NOVICE.value))
            self._success_streak = int(state.get("success_streak", 0))
            self._failure_streak = int(state.get("failure_streak", 0))
            self._last_failure_reason = state.get("last_failure_reason")
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            # Если файл повреждён — начинаем с нуля
            print(f"[TrustLevelManager] Warning: failed to load state from {self._state_file}: {exc}")
            self._level = TrustLevel.NOVICE
            self._success_streak = 0
            self._failure_streak = 0
            self._last_failure_reason = None

    def _save_state(self) -> None:
        """Сохраняет состояние TrustLevelManager в файл."""
        if self._state_file is None:
            return

        state = {
            "level": self._level.value,
            "success_streak": self._success_streak,
            "failure_streak": self._failure_streak,
            "last_failure_reason": self._last_failure_reason,
        }

        try:
            # Создаём директорию, если нужно
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
        except OSError as exc:
            # Логируем, но не прерываем работу
            print(f"[TrustLevelManager] Warning: failed to save state to {self._state_file}: {exc}")

    @property
    def level(self) -> TrustLevel:
        return self._level

    @property
    def success_streak(self) -> int:
        return self._success_streak

    @property
    def failure_streak(self) -> int:
        return self._failure_streak

    @property
    def last_failure_reason(self) -> Optional[str]:
        return self._last_failure_reason

    def can_modify(self, task: Task) -> TrustDecision:
        if not task.current_code or not task.current_code.strip():
            return TrustDecision(allowed=False, current_level=self._level, reason="Empty current_code.")
        if not task.target_path:
            return TrustDecision(allowed=False, current_level=self._level, reason="Empty target_path.")
        if not task.allowed_paths:
            return TrustDecision(allowed=False, current_level=self._level, reason="No allowed_paths provided.")
        if not self._is_path_allowed(task.target_path, task.allowed_paths):
            return TrustDecision(allowed=False, current_level=self._level, reason="target_path is outside allowed_paths.")

        language = self._detect_language(task)

        if language == "javascript":
            target_type = self._resolve_target_type_js(task.current_code, task.target_symbol)
            if target_type is None:
                return TrustDecision(allowed=False, current_level=self._level, reason="Cannot determine target type from JavaScript code.")
        else:
            try:
                tree = ast.parse(task.current_code)
            except SyntaxError as exc:
                return TrustDecision(allowed=False, current_level=self._level, reason=f"Syntax error: {exc}")
            target_type = self._resolve_target_type(tree, task.target_symbol)
            if target_type is None:
                return TrustDecision(allowed=False, current_level=self._level, reason="Cannot determine target type from AST.")

        allowed_types = self.LEVEL_TARGET_TYPES.get(self._level, set())
        if target_type not in allowed_types:
            return TrustDecision(allowed=False, current_level=self._level, reason=f"Trust level {self._level.name} cannot modify {target_type}.")

        return TrustDecision(allowed=True, current_level=self._level, reason=f"Allowed modification of {target_type}.")

    def record_success(self, task: Task) -> None:
        self._success_streak += 1
        self._failure_streak = 0
        self._last_failure_reason = None

        if self._success_streak >= self.promotion_threshold and self._level < TrustLevel.SENIOR:
            self._level = TrustLevel(self._level + 1)
            self._success_streak = 0

        self._save_state()

    def record_failure(self, task: Task, reason: str) -> None:
        self._failure_streak += 1
        self._success_streak = 0
        self._last_failure_reason = reason

        if self._failure_streak >= self.demotion_threshold and self._level > TrustLevel.NOVICE:
            self._level = TrustLevel(self._level - 1)
            self._failure_streak = 0

        self._save_state()

    @staticmethod
    def _normalize_path(path: str) -> str:
        return os.path.normpath(os.path.abspath(path))

    @classmethod
    def _is_path_allowed(cls, target_path: str, allowed_paths: tuple[str, ...]) -> bool:
        if not target_path:
            return False
        target_normalized = cls._normalize_path(target_path)
        for allowed_path in allowed_paths:
            if not allowed_path:
                continue
            allowed_normalized = cls._normalize_path(allowed_path)
            if target_normalized == allowed_normalized:
                return True
            if target_normalized.startswith(allowed_normalized + os.sep):
                return True
        return False

    @staticmethod
    def _detect_language(task: Task) -> str:
        if isinstance(task.metadata, dict):
            return task.metadata.get("language", "python")
        return "python"

    @classmethod
    def _resolve_target_type_js(cls, code: str, target_symbol: Optional[str]) -> Optional[str]:
        if target_symbol:
            escaped = re.escape(target_symbol)
            function_patterns = [
                rf"function\s+{escaped}\s*\(",
                rf"const\s+{escaped}\s*=\s*(?:function|\()",
                rf"let\s+{escaped}\s*=\s*(?:function|\()",
                rf"var\s+{escaped}\s*=\s*(?:function|\()",
                rf"{escaped}\s*:\s*function",
                rf"{escaped}\s*=\s*(?:function|\()",
                rf"async\s+function\s+{escaped}\s*\(",
            ]
            for pattern in function_patterns:
                if re.search(pattern, code):
                    return "function"
            class_pattern = rf"class\s+{escaped}"
            if re.search(class_pattern, code):
                return "class"
            return None

        has_function = bool(re.search(r"function\s+\w+\s*\(|=>", code))
        has_class = bool(re.search(r"class\s+\w+", code))
        if has_function and not has_class:
            return "function"
        if has_class and not has_function:
            return "class"
        return None

    @staticmethod
    def _contains_function(tree: ast.AST) -> bool:
        return any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree))

    @staticmethod
    def _contains_class(tree: ast.AST) -> bool:
        return any(isinstance(node, ast.ClassDef) for node in ast.walk(tree))

    @classmethod
    def _resolve_target_type(cls, tree: ast.AST, target_symbol: Optional[str]) -> Optional[str]:
        if target_symbol:
            function_names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
            class_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
            if target_symbol in function_names:
                return "function"
            if target_symbol in class_names:
                return "class"
            return None
        has_function = cls._contains_function(tree)
        has_class = cls._contains_class(tree)
        if has_function and not has_class:
            return "function"
        if has_class and not has_function:
            return "class"
        return None
