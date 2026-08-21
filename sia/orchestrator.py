from __future__ import annotations

from dataclasses import asdict
from typing import Any, Optional

from .code_agent import CodeAgent, CodeAgentError
from .constitutional_ai_layer import ConstitutionalAILayer
from .evaluation_engine import EvaluationEngine
from .event_logger import EventLogger
from .models import EvaluationResult, Task
from .sandbox_executor import SandboxExecutor
from .tracing import get_tracer
from .trust_level_manager import TrustLevelManager


class Orchestrator:
    def __init__(
        self,
        trust_manager: TrustLevelManager,
        safety_guard: ConstitutionalAILayer,
        code_agent: CodeAgent,
        sandbox_executor: SandboxExecutor,
        evaluation_engine: EvaluationEngine,
        event_logger: EventLogger,
    ) -> None:
        self.trust_manager = trust_manager
        self.safety_guard = safety_guard
        self.code_agent = code_agent
        self.sandbox_executor = sandbox_executor
        self.evaluation_engine = evaluation_engine
        self.event_logger = event_logger
        self.tracer = get_tracer("sia.orchestrator")

    def run_task(
        self,
        task: Task,
        test_code: Optional[str] = None,
        test_suite: Optional[list[str]] = None,
        args_template: Optional[tuple[Any, ...]] = None,
        kwargs_template: Optional[dict[str, Any]] = None,
    ) -> EvaluationResult:
        with self.tracer.start_as_current_span("run_task") as root_span:
            root_span.set_attribute("task.id", task.task_id)
            root_span.set_attribute("task.target_path", task.target_path)
            root_span.set_attribute("task.target_symbol", task.target_symbol or "")

            if test_code is None and isinstance(task.metadata, dict):
                test_code = task.metadata.get("test_code")

            if test_suite is None and isinstance(task.metadata, dict):
                test_suite = task.metadata.get("test_suite")

            if test_suite:
                suite_code = "\n".join(test_suite)
                if test_code:
                    test_code = test_code + "\n" + suite_code
                else:
                    test_code = suite_code

            self._log("task_received", self._task_payload(task))

            try:
                # --- Trust Check ---
                with self.tracer.start_as_current_span("trust_check") as trust_span:
                    trust_decision = self.trust_manager.can_modify(task)
                    trust_span.set_attribute("trust.allowed", trust_decision.allowed)
                    trust_span.set_attribute("trust.level", trust_decision.current_level.name)
                    self._log("trust_decision", asdict(trust_decision))

                if not trust_decision.allowed:
                    root_span.set_attribute("task.rejected_reason", "trust")
                    return self._deny(
                        task=task,
                        stage="trust",
                        reason=trust_decision.reason,
                    )

                # --- Code Generation ---
                with self.tracer.start_as_current_span("code_generation") as codegen_span:
                    codegen_span.set_attribute("llm.model", getattr(self.code_agent, "model_name", "unknown"))
                    try:
                        proposal = self.code_agent.generate_change(task)
                        codegen_span.set_attribute("codegen.success", True)
                    except CodeAgentError as exc:
                        codegen_span.set_attribute("codegen.success", False)
                        codegen_span.set_attribute("codegen.error", str(exc))
                        self._log(
                            "code_agent_error",
                            {
                                "task_id": task.task_id,
                                "error": str(exc),
                            },
                        )
                        return EvaluationResult(
                            task_id=task.task_id,
                            approved=False,
                            details={
                                "stage": "code_agent",
                                "reason": str(exc),
                            },
                        )

                self._log(
                    "change_proposed",
                    {
                        "task_id": proposal.task_id,
                        "model_name": proposal.model_name,
                        "rationale": proposal.rationale,
                        "new_code_length": len(proposal.new_code or ""),
                        "new_code": proposal.new_code,
                    },
                )

                # --- Constitutional Check ---
                with self.tracer.start_as_current_span("constitutional_check") as safety_span:
                    safety_result = self.safety_guard.check(proposal.new_code)
                    safety_span.set_attribute("safety.approved", safety_result.approved)
                    safety_span.set_attribute("safety.violations_count", len(safety_result.violations))
                    self._log("safety_check", asdict(safety_result))

                if not safety_result.approved:
                    reason = "safety_violation"
                    self.trust_manager.record_failure(task, reason)
                    self._log(
                        "trust_updated_after_failure",
                        {
                            "task_id": task.task_id,
                            "level": self.trust_manager.level.name,
                            "reason": reason,
                        },
                    )
                    root_span.set_attribute("task.rejected_reason", "safety")
                    return EvaluationResult(
                        task_id=task.task_id,
                        approved=False,
                        safety_score=0.0,
                        details={
                            "stage": "safety",
                            "violations": list(safety_result.violations),
                            "warnings": list(safety_result.warnings),
                        },
                    )

                # --- Sandbox Execution ---
                with self.tracer.start_as_current_span("sandbox_execution") as sandbox_span:
                    execution_result = self.sandbox_executor.run(
                        proposal.new_code,
                        test_code,
                    )
                    sandbox_span.set_attribute("sandbox.success", execution_result.success)
                    sandbox_span.set_attribute("sandbox.timed_out", execution_result.timed_out)
                    sandbox_span.set_attribute("sandbox.duration_sec", execution_result.duration_sec)
                    self._log("sandbox_execution", asdict(execution_result))

                if not execution_result.success:
                    reason = (
                        execution_result.error
                        or execution_result.stderr
                        or "sandbox_execution_failed"
                    )

                    self.trust_manager.record_failure(task, reason)
                    self._log(
                        "trust_updated_after_failure",
                        {
                            "task_id": task.task_id,
                            "level": self.trust_manager.level.name,
                            "reason": reason,
                        },
                    )
                    root_span.set_attribute("task.rejected_reason", "sandbox")
                    return EvaluationResult(
                        task_id=task.task_id,
                        approved=False,
                        details={
                            "stage": "sandbox",
                            "exit_code": execution_result.exit_code,
                            "timed_out": execution_result.timed_out,
                            "error": execution_result.error,
                            "stderr_tail": (execution_result.stderr or "")[-1000:],
                        },
                    )

                # --- Evaluation ---
                with self.tracer.start_as_current_span("evaluation") as eval_span:
                    evaluation_result = self.evaluation_engine.evaluate(
                        task=task,
                        proposal=proposal,
                        safety_result=safety_result,
                        execution_result=execution_result,
                        test_code=test_code,
                        test_suite=test_suite,
                        args_template=args_template,
                        kwargs_template=kwargs_template,
                    )
                    eval_span.set_attribute("evaluation.approved", evaluation_result.approved)
                    if evaluation_result.performance_gain is not None:
                        eval_span.set_attribute("evaluation.performance_gain", evaluation_result.performance_gain)
                    if evaluation_result.safety_score is not None:
                        eval_span.set_attribute("evaluation.safety_score", evaluation_result.safety_score)
                    if evaluation_result.overall_efficiency_score is not None:
                        eval_span.set_attribute("evaluation.overall_efficiency_score", evaluation_result.overall_efficiency_score)
                    if evaluation_result.cost_savings_usd is not None:
                        eval_span.set_attribute("evaluation.cost_savings_usd", evaluation_result.cost_savings_usd)
                        eval_span.set_attribute("evaluation.cost_reduction", evaluation_result.cost_reduction)
                    self._log("evaluation_result", asdict(evaluation_result))

                if evaluation_result.approved:
                    self.trust_manager.record_success(task)
                    self._log(
                        "trust_updated_after_success",
                        {
                            "task_id": task.task_id,
                            "level": self.trust_manager.level.name,
                        },
                    )
                    root_span.set_attribute("task.approved", True)
                else:
                    reason = "evaluation_not_approved"
                    self.trust_manager.record_failure(task, reason)
                    self._log(
                        "trust_updated_after_failure",
                        {
                            "task_id": task.task_id,
                            "level": self.trust_manager.level.name,
                            "reason": reason,
                        },
                    )
                    root_span.set_attribute("task.approved", False)
                    root_span.set_attribute("task.rejected_reason", "evaluation")

                return evaluation_result

            except Exception as exc:
                import traceback
                traceback.print_exc()
                root_span.set_attribute("task.error", str(exc))
                self._log(
                    "orchestrator_error",
                    {
                        "task_id": task.task_id,
                        "error": str(exc),
                    },
                )

                return EvaluationResult(
                    task_id=task.task_id,
                    approved=False,
                    details={
                        "stage": "orchestrator",
                        "reason": str(exc),
                    },
                )

    def _deny(
        self,
        task: Task,
        stage: str,
        reason: str,
    ) -> EvaluationResult:
        self._log(
            "task_denied",
            {
                "task_id": task.task_id,
                "stage": stage,
                "reason": reason,
            },
        )

        return EvaluationResult(
            task_id=task.task_id,
            approved=False,
            details={
                "stage": stage,
                "reason": reason,
            },
        )

    def _log(self, event_type: str, payload: dict[str, Any]) -> None:
        self.event_logger.log(event_type, payload)

    @staticmethod
    def _task_payload(task: Task) -> dict[str, Any]:
        return {
            "task_id": task.task_id,
            "description": task.description,
            "target_path": task.target_path,
            "target_symbol": task.target_symbol,
            "allowed_paths": list(task.allowed_paths),
            "current_code_length": len(task.current_code or ""),
        }
