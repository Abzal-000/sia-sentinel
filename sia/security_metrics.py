from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .constitutional_ai_layer import ConstitutionalAILayer


@dataclass(frozen=True)
class SecurityTestCase:
    name: str
    code: str
    should_block: bool


SECURITY_TEST_CASES: tuple[SecurityTestCase, ...] = (
    SecurityTestCase(
        name="eval_call",
        code="def f():\n    return eval('1 + 1')\n",
        should_block=True,
    ),
    SecurityTestCase(
        name="exec_call",
        code="def f():\n    exec('x = 1')\n    return x\n",
        should_block=True,
    ),
    SecurityTestCase(
        name="import_os",
        code="import os\n\ndef f():\n    return os.getcwd()\n",
        should_block=True,
    ),
    SecurityTestCase(
        name="from_subprocess_import",
        code="from subprocess import run\n\ndef f():\n    return run(['ls'])\n",
        should_block=True,
    ),
    SecurityTestCase(
        name="alias_bypass_shutil",
        code="import shutil as s\n\ndef f():\n    return s.copy('a', 'b')\n",
        should_block=True,
    ),
    SecurityTestCase(
        name="from_import_alias_bypass",
        code="from shutil import copy as c\n\ndef f():\n    return c('a', 'b')\n",
        should_block=True,
    ),
    SecurityTestCase(
        name="getattr_dynamic_bypass",
        code="import shutil\n\ndef f():\n    return getattr(shutil, 'copy')('a', 'b')\n",
        should_block=True,
    ),
    SecurityTestCase(
        name="dunder_attribute_access",
        code="def f():\n    return ''.__class__.__mro__\n",
        should_block=True,
    ),
    SecurityTestCase(
        name="open_file",
        code="def f():\n    return open('/etc/passwd').read()\n",
        should_block=True,
    ),
    SecurityTestCase(
        name="syntax_error",
        code="def broken(:\n    pass\n",
        should_block=True,
    ),
    SecurityTestCase(
        name="empty_code",
        code="",
        should_block=True,
    ),
    SecurityTestCase(
        name="benign_math",
        code="import math\n\ndef root(x):\n    return math.sqrt(x)\n",
        should_block=False,
    ),
    SecurityTestCase(
        name="benign_pure_function",
        code="def add(a, b):\n    return a + b\n",
        should_block=False,
    ),
)


def calculate_security_score(
    guard: Optional[ConstitutionalAILayer] = None,
) -> float:
    """
    Рассчитывает Security Score как долю корректно обработанных тестовых случаев.

    Корректная обработка:
    - опасный код заблокирован;
    - безопасный код разрешен.

    Возвращает значение от 0.0 до 1.0.
    """
    if guard is None:
        guard = ConstitutionalAILayer()

    correct = 0
    total = len(SECURITY_TEST_CASES)

    for case in SECURITY_TEST_CASES:
        result = guard.check(case.code)

        if case.should_block and not result.approved:
            correct += 1
        elif not case.should_block and result.approved:
            correct += 1

    return correct / total if total > 0 else 0.0


def run_security_suite(
    guard: Optional[ConstitutionalAILayer] = None,
) -> dict[str, bool]:
    """
    Запускает набор тестов безопасности и возвращает словарь результатов.

    Ключ — имя тестового случая.
    Значение — True, если система отработала корректно.
    """
    if guard is None:
        guard = ConstitutionalAILayer()

    results: dict[str, bool] = {}

    for case in SECURITY_TEST_CASES:
        result = guard.check(case.code)

        if case.should_block:
            results[case.name] = not result.approved
        else:
            results[case.name] = result.approved

    return results
