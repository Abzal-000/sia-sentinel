from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Optional

from .models import ExecutionResult

try:
    import docker
    from docker.errors import ImageNotFound
    DOCKER_AVAILABLE = True
except ImportError:
    docker = None
    DOCKER_AVAILABLE = False


class JsSandboxExecutor:
    """Sandbox для выполнения JavaScript-кода в Docker (node:18-slim)."""

    def __init__(
        self,
        image: str = "node:18-slim",
        timeout_sec: int = 30,
        memory_limit: str = "256m",
        nano_cpus: int = 500_000_000,
        network_disabled: bool = True,
    ) -> None:
        self.image = image
        self.timeout_sec = timeout_sec
        self.memory_limit = memory_limit
        self.nano_cpus = nano_cpus
        self.network_disabled = network_disabled

    def _build_test_runner_code(self, code: str, test_code: Optional[str]) -> str:
        return f'''
const solutionCode = {json.dumps(code)};
const testCode = {json.dumps(test_code or "")};

try {{
    eval(solutionCode);
}} catch (e) {{
    console.error("SOLUTION_IMPORT_ERROR: " + e.message);
    process.exit(2);
}}

if (testCode) {{
    try {{
        eval(testCode);
        console.log("TESTS_PASSED");
    }} catch (e) {{
        console.error("TEST_FAILED: " + e.message);
        process.exit(3);
    }}
}}
'''

    def run(self, code: str, test_code: Optional[str] = None) -> ExecutionResult:
        if not DOCKER_AVAILABLE:
            return ExecutionResult(
                success=False,
                error="Docker SDK for Python is not installed.",
            )

        try:
            client = docker.from_env()
            client.ping()
        except Exception as exc:
            return ExecutionResult(
                success=False,
                error=f"Docker daemon is not available: {exc}",
            )

        # Автоматическое скачивание образа
        try:
            client.images.get(self.image)
        except ImageNotFound:
            try:
                print(f"[JsSandbox] Image {self.image} not found locally. Pulling...")
                client.images.pull(self.image)
                print(f"[JsSandbox] Image {self.image} pulled successfully.")
            except Exception as pull_exc:
                return ExecutionResult(
                    success=False,
                    error=f"Failed to pull Docker image {self.image}: {pull_exc}",
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            runner_path = Path(tmpdir) / "runner.js"
            runner_path.write_text(
                self._build_test_runner_code(code, test_code),
                encoding="utf-8",
            )

            container = None
            start_time = time.time()
            stdout = ""
            stderr = ""
            exit_code = None
            timed_out = False
            error_msg = None

            try:
                container = client.containers.create(
                    image=self.image,
                    command=["node", "/workspace/runner.js"],
                    volumes={
                        tmpdir: {"bind": "/workspace", "mode": "ro"}
                    },
                    network_disabled=self.network_disabled,
                    mem_limit=self.memory_limit,
                    nano_cpus=self.nano_cpus,
                    working_dir="/workspace",
                )

                container.start()

                try:
                    result = container.wait(timeout=self.timeout_sec)
                    exit_code = result.get("StatusCode")
                except Exception as wait_exc:
                    timed_out = True
                    try:
                        container.kill()
                    except Exception:
                        pass
                    error_msg = f"Execution timed out or failed to wait: {wait_exc}"

                stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

            except Exception as exc:
                error_msg = f"JS Sandbox execution error: {exc}"
            finally:
                if container is not None:
                    try:
                        container.remove(force=True)
                    except Exception:
                        pass

            duration = time.time() - start_time

            success = (
                exit_code == 0
                and not timed_out
                and error_msg is None
            )

            return ExecutionResult(
                success=success,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration_sec=duration,
                timed_out=timed_out,
                error=error_msg,
                container_id=container.id if container else None,
            )
