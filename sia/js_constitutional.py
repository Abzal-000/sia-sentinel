from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class JsSafetyCheckResult:
    approved: bool
    violations: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)


class JsConstitutionalLayer:
    """Constitutional AI Layer для JavaScript: блокирует опасные паттерны."""

    DANGEROUS_PATTERNS = (
        "require('fs')",
        'require("fs")',
        "require('child_process')",
        'require("child_process")',
        "require('net')",
        'require("net")',
        "require('http')",
        'require("http")',
        "require('https')",
        'require("https")',
        "eval(",
        "Function(",
        "process.exit(",
        "process.env",
        "__proto__",
        "constructor.prototype",
    )

    DANGEROUS_GLOBALS = (
        "global.process",
        "globalThis.process",
    )

    def check(self, code: str) -> JsSafetyCheckResult:
        if not code or not code.strip():
            return JsSafetyCheckResult(
                approved=False,
                violations=("Empty code is not allowed",),
            )

        violations = []
        warnings = []

        for pattern in self.DANGEROUS_PATTERNS:
            if pattern in code:
                violations.append(f"Dangerous pattern detected: {pattern}")

        for pattern in self.DANGEROUS_GLOBALS:
            if pattern in code:
                violations.append(f"Dangerous global access: {pattern}")

        # Предупреждения для потенциально рискованных, но не блокирующих паттернов
        if "setTimeout(" in code or "setInterval(" in code:
            warnings.append("Async timer detected: potential for hanging execution")

        approved = len(violations) == 0

        return JsSafetyCheckResult(
            approved=approved,
            violations=tuple(violations),
            warnings=tuple(warnings),
        )
