from __future__ import annotations

import unittest
from unittest.mock import patch

from sia.cli import parse_args, resolve_api_key, main


class CLITestCase(unittest.TestCase):
    def test_parse_required_args(self) -> None:
        args = parse_args(
            [
                "--description",
                "Optimize fib",
                "--target-path",
                "src/fib.py",
                "--current-code",
                "def fib(n):\n    return n\n",
            ]
        )

        self.assertEqual(args.description, "Optimize fib")
        self.assertEqual(args.target_path, "src/fib.py")
        self.assertEqual(args.current_code, "def fib(n):\n    return n\n")
        self.assertEqual(args.allowed_paths, ())
        self.assertIsNone(args.test_code)
        self.assertEqual(args.model, "nvidia/nemotron-3-ultra-550b-a55b")
        self.assertEqual(args.base_url, "https://integrate.api.nvidia.com/v1")
        self.assertEqual(args.timeout, 30)
        self.assertEqual(args.memory_limit, "256m")

    def test_parse_all_args(self) -> None:
        args = parse_args(
            [
                "--description",
                "Optimize fib",
                "--target-path",
                "src/fib.py",
                "--current-code",
                "def fib(n):\n    return n\n",
                "--target-symbol",
                "fib",
                "--allowed-paths",
                "src/fib.py",
                "src",
                "--test-code",
                "assert fib(1) == 1",
                "--model",
                "custom-model",
                "--base-url",
                "http://localhost:8000/v1",
                "--timeout",
                "10",
                "--memory-limit",
                "128m",
                "--log-dir",
                "custom_logs",
            ]
        )

        self.assertEqual(args.target_symbol, "fib")
        self.assertEqual(args.allowed_paths, ["src/fib.py", "src"])
        self.assertEqual(args.test_code, "assert fib(1) == 1")
        self.assertEqual(args.model, "custom-model")
        self.assertEqual(args.base_url, "http://localhost:8000/v1")
        self.assertEqual(args.timeout, 10)
        self.assertEqual(args.memory_limit, "128m")
        self.assertEqual(args.log_dir, "custom_logs")

    def test_missing_required_args_exits(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args([])

    def test_resolve_api_key_from_env(self) -> None:
        with patch.dict("os.environ", {"NVIDIA_API_KEY": "env-key"}):
            api_key = resolve_api_key()

        self.assertEqual(api_key, "env-key")

    def test_main_fails_without_api_key(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with patch("sia.cli.resolve_api_key", return_value=None):
                exit_code = main(
                    [
                        "--description",
                        "Optimize",
                        "--target-path",
                        "src/fib.py",
                        "--current-code",
                        "def fib(n):\n    return n\n",
                    ]
                )

        self.assertEqual(exit_code, 1)
