from __future__ import annotations

import unittest
from unittest.mock import patch, MagicMock

from sia.sandbox_executor import SandboxExecutor


class SandboxExecutorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.executor = SandboxExecutor(timeout_sec=5, memory_limit="128m")

    @patch("sia.sandbox_executor.docker")
    def test_successful_run(self, mock_docker: MagicMock) -> None:
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client

        mock_container = MagicMock()
        mock_client.containers.create.return_value = mock_container
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.side_effect = [b"TESTS_PASSED\n", b""]

        result = self.executor.run("def foo(): pass", "foo()")

        self.assertTrue(result.success)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.exit_code, 0)

        create_kwargs = mock_client.containers.create.call_args.kwargs
        self.assertTrue(create_kwargs["network_disabled"])
        self.assertEqual(create_kwargs["mem_limit"], "128m")
        self.assertIn("SIA_MAX_MEM_BYTES", create_kwargs["environment"])

        mock_container.remove.assert_called_once_with(force=True)

    @patch("sia.sandbox_executor.docker")
    def test_timeout_kills_container(self, mock_docker: MagicMock) -> None:
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client

        mock_container = MagicMock()
        mock_client.containers.create.return_value = mock_container

        import requests
        mock_container.wait.side_effect = requests.exceptions.ReadTimeout()
        mock_container.logs.side_effect = [b"", b""]

        result = self.executor.run("while True: pass")

        self.assertFalse(result.success)
        self.assertTrue(result.timed_out)
        mock_container.kill.assert_called_once()
        mock_container.remove.assert_called_once_with(force=True)

    @patch("sia.sandbox_executor.docker")
    def test_docker_not_available(self, mock_docker: MagicMock) -> None:
        mock_docker.from_env.side_effect = Exception("Docker daemon not found")

        result = self.executor.run("def foo(): pass")

        self.assertFalse(result.success)
        self.assertIn("Docker daemon is not available", result.error or "")

    def test_memory_limit_parsing(self) -> None:
        executor = SandboxExecutor(memory_limit="512m")
        self.assertEqual(executor._parse_memory_limit_to_bytes(), 512 * 1024 * 1024)

        executor = SandboxExecutor(memory_limit="1g")
        self.assertEqual(executor._parse_memory_limit_to_bytes(), 1024 * 1024 * 1024)

        executor = SandboxExecutor(memory_limit="256k")
        self.assertEqual(executor._parse_memory_limit_to_bytes(), 256 * 1024)

    @patch("sia.sandbox_executor.docker")
    def test_container_removed_on_exception(self, mock_docker: MagicMock) -> None:
        mock_client = MagicMock()
        mock_docker.from_env.return_value = mock_client

        mock_container = MagicMock()
        mock_client.containers.create.return_value = mock_container
        mock_container.start.side_effect = RuntimeError("Unexpected error")

        result = self.executor.run("def foo(): pass")

        self.assertFalse(result.success)
        mock_container.remove.assert_called_once_with(force=True)
