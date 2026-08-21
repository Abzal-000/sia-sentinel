from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional, Set

from .models import SafetyCheckResult


@dataclass(frozen=True)
class ConstitutionalRule:
    rule_id: str
    description: str


BANNED_MODULES: Set[str] = {
    "os",
    "subprocess",
    "shutil",
    "socket",
    "socketserver",
    "http",
    "httpx",
    "requests",
    "urllib",
    "aiohttp",
    "ctypes",
    "importlib",
    "pickle",
    "marshal",
    "sys",
    "builtins",
    "pathlib",
    "signal",
    "threading",
    "multiprocessing",
    "asyncio",
    "io",
    "tempfile",
    "ssl",
    "ftplib",
    "smtplib",
    "poplib",
    "imaplib",
    "telnetlib",
    "xmlrpc",
    "webbrowser",
    "code",
    "codeop",
    "compileall",
    "resource",
}

BANNED_CALL_NAMES: Set[str] = {
    "eval",
    "exec",
    "compile",
    "open",
    "__import__",
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
    "breakpoint",
    "input",
}

DUNDER_TOKENS: Set[str] = {
    "__import__",
    "__builtins__",
    "__subclasses__",
    "__globals__",
    "__code__",
    "__class__",
    "__base__",
    "__mro__",
    "__dict__",
    "__module__",
    "__qualname__",
    "__self__",
    "__func__",
    "__loader__",
    "__spec__",
}


class _ConstitutionalASTVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.violations: list[str] = []
        self.warnings: list[str] = []
        self.module_aliases: dict[str, str] = {}
        self.variable_aliases: dict[str, str] = {}

    def _add_violation(self, rule_id: str, detail: str) -> None:
        self.violations.append(f"{rule_id}: {detail}")

    def _add_warning(self, rule_id: str, detail: str) -> None:
        self.warnings.append(f"{rule_id}: {detail}")

    @staticmethod
    def _module_root(module_name: str) -> str:
        return (module_name or "").split(".")[0]

    def _module_is_banned(self, module_name: str) -> bool:
        if not module_name:
            return False

        return self._module_root(module_name) in BANNED_MODULES

    def _full_name_is_banned(self, full_name: Optional[str]) -> bool:
        if not full_name:
            return False

        if full_name in BANNED_CALL_NAMES:
            return True

        if self._module_root(full_name) in BANNED_MODULES:
            return True

        return False

    def _resolve_attribute_full_name(self, node: ast.Attribute) -> Optional[str]:
        parts: list[str] = []
        current: ast.expr = node

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            base = current.id
            mapped = self.variable_aliases.get(base) or self.module_aliases.get(base) or base
            return ".".join([mapped] + list(reversed(parts)))

        return None

    def _store_variable_targets(self, targets: list[ast.expr], mapped_name: str) -> None:
        for target in targets:
            if isinstance(target, ast.Name):
                self.variable_aliases[target.id] = mapped_name

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            module_name = alias.name
            local_name = alias.asname or module_name.split(".")[0]

            self.module_aliases[local_name] = module_name

            if self._module_is_banned(module_name):
                self._add_violation(
                    "no-dangerous-imports",
                    f"import of '{module_name}' is prohibited",
                )

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level and node.level > 0:
            self._add_violation(
                "no-relative-imports",
                "relative imports are prohibited",
            )

        module_name = node.module or ""

        if module_name and self._module_is_banned(module_name):
            self._add_violation(
                "no-dangerous-imports",
                f"import from '{module_name}' is prohibited",
            )

        for alias in node.names:
            local_name = alias.asname or alias.name
            full_name = f"{module_name}.{alias.name}" if module_name else alias.name

            self.module_aliases[local_name] = full_name

            if self._full_name_is_banned(full_name):
                self._add_violation(
                    "no-dangerous-imports",
                    f"import of '{full_name}' is prohibited",
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        mapped_name: Optional[str] = None

        if isinstance(node.value, ast.Name):
            name = node.value.id
            mapped_name = self.variable_aliases.get(name) or self.module_aliases.get(name) or name

            if self._full_name_is_banned(mapped_name):
                self._add_violation(
                    "no-dangerous-references",
                    f"assignment references prohibited symbol '{mapped_name}'",
                )

        elif isinstance(node.value, ast.Attribute):
            full_name = self._resolve_attribute_full_name(node.value)
            mapped_name = full_name

            if full_name and self._full_name_is_banned(full_name):
                self._add_violation(
                    "no-dangerous-references",
                    f"assignment references prohibited symbol '{full_name}'",
                )

        if mapped_name:
            self._store_variable_targets(node.targets, mapped_name)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        if isinstance(func, ast.Name):
            name = func.id

            if name in BANNED_CALL_NAMES:
                self._add_violation(
                    "no-dangerous-calls",
                    f"call to '{name}' is prohibited",
                )

            mapped = self.variable_aliases.get(name) or self.module_aliases.get(name)

            if mapped and self._full_name_is_banned(mapped):
                self._add_violation(
                    "no-dangerous-calls",
                    f"call to aliased prohibited symbol '{mapped}' is prohibited",
                )

        elif isinstance(func, ast.Attribute):
            full_name = self._resolve_attribute_full_name(func)

            if full_name and self._full_name_is_banned(full_name):
                self._add_violation(
                    "no-dangerous-calls",
                    f"call to '{full_name}' is prohibited",
                )

            if func.attr in DUNDER_TOKENS:
                self._add_violation(
                    "no-dunder-access",
                    f"call accesses dunder attribute '{func.attr}'",
                )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in DUNDER_TOKENS:
            self._add_violation(
                "no-dunder-access",
                f"access to dunder attribute '{node.attr}' is prohibited",
            )

        full_name = self._resolve_attribute_full_name(node)

        if full_name and self._full_name_is_banned(full_name):
            self._add_violation(
                "no-dangerous-attribute",
                f"access to prohibited symbol '{full_name}'",
            )

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            for token in DUNDER_TOKENS:
                if token in node.value:
                    self._add_violation(
                        "no-dunder-string",
                        f"string literal contains prohibited dunder token '{token}'",
                    )
                    break

        self.generic_visit(node)


class ConstitutionalAILayer:
    def __init__(self) -> None:
        self.rules: tuple[ConstitutionalRule, ...] = (
            ConstitutionalRule(
                rule_id="syntax-valid",
                description="Code must be syntactically valid Python.",
            ),
            ConstitutionalRule(
                rule_id="no-empty-code",
                description="Code changes must not be empty.",
            ),
            ConstitutionalRule(
                rule_id="no-dangerous-imports",
                description="Imports of privileged, filesystem, network, or process modules are prohibited.",
            ),
            ConstitutionalRule(
                rule_id="no-dangerous-calls",
                description="Calls to eval, exec, open, __import__, getattr, setattr, and similar builtins are prohibited.",
            ),
            ConstitutionalRule(
                rule_id="no-dangerous-references",
                description="Assignments must not create aliases to prohibited symbols.",
            ),
            ConstitutionalRule(
                rule_id="no-dunder-access",
                description="Access to dangerous dunder attributes and tokens is prohibited.",
            ),
            ConstitutionalRule(
                rule_id="no-relative-imports",
                description="Relative imports are prohibited because their origin cannot be safely verified.",
            ),
        )

    def check(self, code: str) -> SafetyCheckResult:
        if code is None or not code.strip():
            return SafetyCheckResult(
                approved=False,
                violations=("no-empty-code: code change is empty",),
                warnings=(),
            )

        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return SafetyCheckResult(
                approved=False,
                violations=(f"syntax-valid: {exc}",),
                warnings=(),
            )

        visitor = _ConstitutionalASTVisitor()
        visitor.visit(tree)

        violations = tuple(dict.fromkeys(visitor.violations))
        warnings = tuple(dict.fromkeys(visitor.warnings))

        return SafetyCheckResult(
            approved=len(violations) == 0,
            violations=violations,
            warnings=warnings,
        )
