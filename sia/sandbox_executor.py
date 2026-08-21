from __future__ import annotations

import time
import tempfile
from pathlib import Path
from typing import Optional

from .models import ExecutionResult

try:
    import docker
    from docker.errors import ImageNotFound
    DOCKER_AVAILABLE = True
except ImportError:
    docker = None  # type: ignore[assignment]
    ImageNotFound = Exception  # type: ignore[misc,assignment]
    DOCKER_AVAILABLE = False


class SandboxExecutor:
    def __init__(
        self,
        image: str = "python:3.11-slim",
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

    def _parse_memory_limit_to_bytes(self) -> int:
        s = self.memory_limit.strip().lower()
        if not s:
            return 0
        multiplier = 1
        if s.endswith("m"):
            multiplier = 1024 * 1024
            s = s[:-1]
        elif s.endswith("g"):
            multiplier = 1024 * 1024 * 1024
            s = s[:-1]
        elif s.endswith("k"):
            multiplier = 1024
            s = s[:-1]
        try:
            return int(float(s) * multiplier)
        except ValueError:
            return 0

    def _build_test_runner_code(self, code: str, test_code: Optional[str]) -> str:
        return f'''
import sys
import os
import resource

def apply_limits():
    try:
        max_mem = int(os.environ.get("SIA_MAX_MEM_BYTES", "0"))
        if max_mem > 0:
            resource.setrlimit(resource.RLIMIT_AS, (max_mem, max_mem))
    except Exception:
        pass

def main():
    apply_limits()

    solution_code = {repr(code)}
    test_code = {repr(test_code or "")}

    env = {{"__name__": "__main__"}}
    try:
        exec(solution_code, env)
    except Exception as e:
        print("SOLUTION_IMPORT_ERROR: " + str(e), file=sys.stderr)
        sys.exit(2)

    if test_code:
        try:
            exec(test_code, env)
            print("TESTS_PASSED")
        except Exception as e:
            print("TEST_FAILED: " + str(e), file=sys.stderr)
            sys.exit(3)

if __name__ == "__main__":
    main()
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

        # АВТОМАТИЧЕСКОЕ СКАЧИВАНИЕ ОБРАЗА
        try:
            client.images.get(self.image)
        except ImageNotFound:
            try:
                print(f"[Sandbox] Image {self.image} not found locally. Pulling...")
                client.images.pull(self.image)
                print(f"[Sandbox] Image {self.image} pulled successfully.")
            except Exception as pull_exc:
                return ExecutionResult(
                    success=False,
                    error=f"Failed to pull Docker image {self.image}: {pull_exc}",
                )

        mem_limit_bytes = self._parse_memory_limit_to_bytes()

        with tempfile.TemporaryDirectory() as tmpdir:
            runner_path = Path(tmpdir) / "runner.py"
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
                    command=["python", "/workspace/runner.py"],
                    volumes={
                        tmpdir: {"bind": "/workspace", "mode": "ro"}
                    },
                    network_disabled=self.network_disabled,
                    mem_limit=self.memory_limit,
                    nano_cpus=self.nano_cpus,
                    environment={
                        "SIA_MAX_MEM_BYTES": str(mem_limit_bytes),
                        "PYTHONUNBUFFERED": "1",
                    },
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
                error_msg = f"Sandbox execution error: {exc}"
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
