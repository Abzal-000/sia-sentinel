from __future__ import annotations

import unittest

from sia.constitutional_ai_layer import ConstitutionalAILayer


class ConstitutionalAILayerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.guard = ConstitutionalAILayer()

    def assert_approved(self, code: str) -> None:
        result = self.guard.check(code)
        self.assertTrue(result.approved, msg=str(result.violations))
        self.assertEqual(result.violations, ())

    def assert_denied(self, code: str) -> None:
        result = self.guard.check(code)
        self.assertFalse(result.approved)
        self.assertTrue(result.violations)

    def test_benign_math_code_approved(self) -> None:
        code = """
import math


def root(x):
    return math.sqrt(x)
"""
        self.assert_approved(code)

    def test_benign_dict_method_approved(self) -> None:
        code = """
def get_value(data):
    return data.get("value", 0)
"""
        self.assert_approved(code)

    def test_eval_denied(self) -> None:
        code = """
def bad():
    return eval("1 + 1")
"""
        self.assert_denied(code)

    def test_exec_denied(self) -> None:
        code = """
def bad():
    exec("x = 1")
    return x
"""
        self.assert_denied(code)

    def test_open_denied(self) -> None:
        code = """
def bad():
    return open("/etc/passwd").read()
"""
        self.assert_denied(code)

    def test_import_os_denied(self) -> None:
        code = """
import os


def bad():
    return os.getcwd()
"""
        self.assert_denied(code)

    def test_from_subprocess_import_run_denied(self) -> None:
        code = """
from subprocess import run


def bad():
    return run(["ls"])
"""
        self.assert_denied(code)

    def test_import_shutil_alias_denied(self) -> None:
        code = """
import shutil as s


def bad():
    return s.copy("a", "b")
"""
        self.assert_denied(code)

    def test_from_shutil_import_copy_alias_denied(self) -> None:
        code = """
from shutil import copy as c


def bad():
    return c("a", "b")
"""
        self.assert_denied(code)

    def test_getattr_dynamic_access_denied(self) -> None:
        code = """
import shutil


def bad():
    return getattr(shutil, "copy")("a", "b")
"""
        self.assert_denied(code)

    def test_getattr_with_variable_denied(self) -> None:
        code = """
def bad(obj, name):
    return getattr(obj, name)
"""
        self.assert_denied(code)

    def test_dunder_attribute_denied(self) -> None:
        code = """
def bad():
    return "".__class__.__mro__
"""
        self.assert_denied(code)

    def test_dunder_string_literal_denied(self) -> None:
        code = """
def bad():
    return "__subclasses__"
"""
        self.assert_denied(code)

    def test_syntax_error_denied(self) -> None:
        code = """
def broken(:
    pass
"""
        self.assert_denied(code)

    def test_empty_code_denied(self) -> None:
        self.assert_denied("")
