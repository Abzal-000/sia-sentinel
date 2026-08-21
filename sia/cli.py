from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from .code_agent import CodeAgent
from .constitutional_ai_layer import ConstitutionalAILayer
from .evaluation_engine import EvaluationEngine
from .event_logger import EventLogger
from .models import Task
from .orchestrator import Orchestrator
from .multi_agent import MultiAgentOrchestrator
from .sandbox_executor import SandboxExecutor
from .trust_level_manager import TrustLevelManager


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sia",
        description="Self-Improving Agent CLI",
    )

    parser.add_argument(
        "--description",
        required=True,
        help="Task description",
    )

    parser.add_argument(
        "--target-path",
        required=True,
        help="Target file path",
    )

    parser.add_argument(
        "--current-code",
        required=True,
        help="Current code to optimize",
    )

    parser.add_argument(
        "--target-symbol",
        help="Target function or class name",
    )

    parser.add_argument(
        "--allowed-paths",
        nargs="*",
        default=(),
        help="Allowed paths for modification",
    )

    parser.add_argument(
        "--test-code",
        help="Test code to run in sandbox",
    )

    parser.add_argument(
        "--test-suite",
        default=None,
        help="JSON array of test statements, e.g. '[\"assert fib(0) == 0\"]'",
    )

    parser.add_argument(
        "--test-suite-file",
        default=None,
        help="Path to a JSON file containing an array of test statements",
    )

    parser.add_argument(
        "--model",
        default="nvidia/nemotron-3-ultra-550b-a55b",
        help="LLM model name",
    )

    parser.add_argument(
        "--base-url",
        default="https://integrate.api.nvidia.com/v1",
        help="LLM API base URL",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Sandbox timeout in seconds",
    )

    parser.add_argument(
        "--memory-limit",
        default="256m",
        help="Sandbox memory limit",
    )

    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory for event logs",
    )

    parser.add_argument(
        "--benchmark-args",
        default=None,
        help="JSON array of positional arguments for benchmark, e.g. '[10]'",
    )

    parser.add_argument(
        "--benchmark-kwargs",
        default=None,
        help="JSON object of keyword arguments for benchmark, e.g. '{}'",
    )

    parser.add_argument(
        "--llm-timeout",
        type=float,
        default=180.0,
        help="Timeout in seconds for LLM API requests",
    )

    parser.add_argument(
        "--enable-tracing",
        action="store_true",
        default=False,
        help="Enable OpenTelemetry tracing",
    )

    parser.add_argument(
        "--tracing-exporter",
        choices=["console", "file", "both", "otlp"],
        default="both",
        help="Tracing exporter type",
    )

    parser.add_argument(
        "--otlp-endpoint",
        default=None,
        help="OTLP collector endpoint URL (e.g. http://localhost:4318/v1/traces)",
    )

    parser.add_argument(
        "--multi-agent",
        action="store_true",
        default=False,
        help="Use multi-agent architecture instead of single orchestrator",
    )

    parser.add_argument(
        "--compute-price-per-hour",
        type=float,
        default=None,
        help="Enable Proof-of-Savings costing: USD per hour of occupied compute",
    )

    return parser.parse_args(argv)


def resolve_api_key() -> Optional[str]:
    from .config import resolve_env

    api_key = resolve_env("NVIDIA_API_KEY")

    if api_key:
        return api_key

    try:
        from google.colab import userdata

        api_key = userdata.get("NVIDIA_API_KEY")
        if api_key:
            return api_key
    except Exception:
        pass

    return None


def _build_evaluation_engine(args: argparse.Namespace) -> EvaluationEngine:
    """EvaluationEngine с опциональной тарификацией для Proof-of-Savings."""
    from .cost_model import PricingConfig

    pricing = (
        PricingConfig(compute_usd_per_hour=args.compute_price_per_hour)
        if getattr(args, "compute_price_per_hour", None) is not None
        else None
    )

    return EvaluationEngine(pricing=pricing)


def build_orchestrator(
    args: argparse.Namespace,
    api_key: Optional[str],
) -> Orchestrator:
    trust_manager = TrustLevelManager()
    safety_guard = ConstitutionalAILayer()

    code_agent = CodeAgent(
        model_name=args.model,
        api_key=api_key,
        base_url=args.base_url,
        request_timeout=args.llm_timeout,
    )

    sandbox_executor = SandboxExecutor(
        timeout_sec=args.timeout,
        memory_limit=args.memory_limit,
    )

    evaluation_engine = _build_evaluation_engine(args)
    event_logger = EventLogger(log_dir=args.log_dir)

    return Orchestrator(
        trust_manager=trust_manager,
        safety_guard=safety_guard,
        code_agent=code_agent,
        sandbox_executor=sandbox_executor,
        evaluation_engine=evaluation_engine,
        event_logger=event_logger,
    )


def build_multi_agent_orchestrator(
    args: argparse.Namespace,
    api_key: Optional[str],
):
    from .multi_agent import GeneratorAgent, SecurityAgent, TestAgent, RefactorAgent

    trust_manager = TrustLevelManager()
    safety_guard = ConstitutionalAILayer()

    generator_agent = GeneratorAgent(
        name="generator",
        model_name=args.model,
        api_key=api_key,
        base_url=args.base_url,
        request_timeout=args.llm_timeout,
    )

    security_agent = SecurityAgent(
        name="security",
        model_name=args.model,
        api_key=api_key,
        base_url=args.base_url,
        request_timeout=args.llm_timeout,
    )

    test_agent = TestAgent(
        name="test",
        model_name=args.model,
        api_key=api_key,
        base_url=args.base_url,
        request_timeout=args.llm_timeout,
    )

    refactor_agent = RefactorAgent(
        name="refactor",
        model_name=args.model,
        api_key=api_key,
        base_url=args.base_url,
        request_timeout=args.llm_timeout,
    )

    sandbox_executor = SandboxExecutor(
        timeout_sec=args.timeout,
        memory_limit=args.memory_limit,
    )

    evaluation_engine = _build_evaluation_engine(args)
    event_logger = EventLogger(log_dir=args.log_dir)

    return MultiAgentOrchestrator(
        trust_manager=trust_manager,
        safety_guard=safety_guard,
        generator_agent=generator_agent,
        security_agent=security_agent,
        test_agent=test_agent,
        refactor_agent=refactor_agent,
        sandbox_executor=sandbox_executor,
        evaluation_engine=evaluation_engine,
        event_logger=event_logger,
    )


def _ensure_utf8_console() -> None:
    """Re-wrap a real Windows console so Unicode output is not mangled."""
    if sys.platform != "win32":
        return

    import io

    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name)

        if not stream.isatty() or not hasattr(stream, "buffer"):
            continue

        try:
            setattr(
                sys,
                stream_name,
                io.TextIOWrapper(stream.buffer, encoding="utf-8", errors="replace"),
            )
        except (ValueError, OSError):
            continue


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    _ensure_utf8_console()

    tracing_enabled = args.enable_tracing
    if tracing_enabled:
        from .tracing import init_tracing
        init_tracing(
            service_name="sia",
            exporter=args.tracing_exporter,
            otlp_endpoint=args.otlp_endpoint,
        )

    try:
        api_key = resolve_api_key()

        if not api_key:
            print(
                "Error: NVIDIA_API_KEY is not configured. "
                "Set it as an environment variable or in Colab Secrets.",
                file=sys.stderr,
            )
            return 1

        if args.multi_agent:
            orchestrator = build_multi_agent_orchestrator(args, api_key)
            print("Using multi-agent architecture")
        else:
            orchestrator = build_orchestrator(args, api_key)
            print("Using single-orchestrator architecture")

        task = Task(
            description=args.description,
            target_path=args.target_path,
            current_code=args.current_code,
            target_symbol=args.target_symbol,
            allowed_paths=tuple(args.allowed_paths),
            metadata={"test_code": args.test_code} if args.test_code else {},
        )

        benchmark_args = None
        benchmark_kwargs = None

        if args.benchmark_args:
            try:
                benchmark_args = tuple(json.loads(args.benchmark_args))
            except json.JSONDecodeError:
                print("Error: --benchmark-args must be a valid JSON array", file=sys.stderr)
                return 1

        if args.benchmark_kwargs:
            try:
                benchmark_kwargs = json.loads(args.benchmark_kwargs)
            except json.JSONDecodeError:
                print("Error: --benchmark-kwargs must be a valid JSON object", file=sys.stderr)
                return 1

        test_suite = None

        if args.test_suite:
            try:
                parsed_suite = json.loads(args.test_suite)
            except json.JSONDecodeError:
                print("Error: --test-suite must be a valid JSON array of strings", file=sys.stderr)
                return 1

            if not isinstance(parsed_suite, list) or not all(isinstance(item, str) for item in parsed_suite):
                print("Error: --test-suite must be a JSON array of strings", file=sys.stderr)
                return 1

            test_suite = parsed_suite

        if args.test_suite_file:
            try:
                with open(args.test_suite_file, "r", encoding="utf-8-sig") as f:
                    file_suite = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error: Failed to read test suite file: {e}", file=sys.stderr)
                return 1

            if not isinstance(file_suite, list) or not all(isinstance(item, str) for item in file_suite):
                print("Error: test suite file must contain a JSON array of strings", file=sys.stderr)
                return 1

            test_suite = file_suite

        result = orchestrator.run_task(
            task,
            test_code=args.test_code,
            test_suite=test_suite,
            args_template=benchmark_args,
            kwargs_template=benchmark_kwargs,
        )

        if result.approved:
            print("Task approved.")
        else:
            print("Task rejected.")

        if result.performance_gain is not None:
            print(f"Performance gain: {result.performance_gain:.2%}")

        if result.safety_score is not None:
            print(f"Safety score: {result.safety_score:.2f}")

        if result.semantic_equivalence is not None:
            print(f"Semantic equivalence: {'Yes' if result.semantic_equivalence else 'No'}")

        if getattr(result, "semantic_test_results", None):
            suite_result = result.semantic_test_results
            print(f"Semantic tests: {suite_result.get('passed_new', 0)}/{suite_result.get('total', 0)} passed")

        if result.quality_score is not None:
            print(f"Quality score: {result.quality_score:.2f}")

        if result.security_vulnerabilities is not None:
            print(f"Security vulnerabilities: {result.security_vulnerabilities}")

        if result.overall_efficiency_score is not None:
            print(f"Overall efficiency score: {result.overall_efficiency_score:.2f}")

        if result.cost_savings_usd is not None:
            print(
                f"Cost savings: ${result.cost_savings_usd:.6f} per run "
                f"({result.cost_reduction:.1%} reduction)"
            )

        if result.details.get("savings_usd_per_1k_runs") is not None:
            print(
                f"Projected savings: ${result.details['savings_usd_per_1k_runs']:.2f} per 1,000 runs"
            )

        if result.details:
            print(f"Details: {result.details}")

        return 0 if result.approved else 1

    finally:
        if tracing_enabled:
            from .tracing import shutdown_tracing
            shutdown_tracing()


if __name__ == "__main__":
    raise SystemExit(main())
