from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Optional

from ..constitutional_ai_layer import ConstitutionalAILayer
from ..evaluation_engine import EvaluationEngine
from ..event_logger import EventLogger
from ..models import EvaluationResult, Task
from ..sandbox_executor import SandboxExecutor
from ..tracing import get_tracer
from ..trust_level_manager import TrustLevelManager
from .base_agent import AgentResult
from .generator_agent import GeneratorAgent
from .refactor_agent import RefactorAgent
from .security_agent import SecurityAgent
from .test_agent import TestAgent




def _to_dict(obj):
    """Безопасная конвертация объекта в dict для логирования."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    elif hasattr(obj, "__dict__"):
        return vars(obj)
    else:
        return {"value": str(obj)}

class MultiAgentOrchestrator:
    """Оркестратор многоагентной архитектуры SIA."""

    def __init__(
        self,
        trust_manager: TrustLevelManager,
        safety_guard: ConstitutionalAILayer,
        generator_agent: GeneratorAgent,
        security_agent: SecurityAgent,
        test_agent: TestAgent,
        refactor_agent: RefactorAgent,
        sandbox_executor: SandboxExecutor,
        evaluation_engine: EvaluationEngine,
        event_logger: EventLogger,
    ) -> None:
        self.trust_manager = trust_manager
        self.safety_guard = safety_guard
        self.generator_agent = generator_agent
        self.security_agent = security_agent
        self.test_agent = test_agent
        self.refactor_agent = refactor_agent
        self.sandbox_executor = sandbox_executor
        self.evaluation_engine = evaluation_engine
        self.event_logger = event_logger
        self.tracer = get_tracer("sia.multi_agent_orchestrator")

    def run_task(
        self,
        task: Task,
        test_code: Optional[str] = None,
        test_suite: Optional[list[str]] = None,
        args_template: Optional[tuple[Any, ...]] = None,
        kwargs_template: Optional[dict[str, Any]] = None,
    ) -> EvaluationResult:
        """Полный цикл многоагентной обработки задачи."""

        # Инициализация контекста для передачи между агентами
        context: dict[str, Any] = {
            "task": task,
            "test_code": test_code,
            "test_suite": test_suite,
            "args_template": args_template,
            "kwargs_template": kwargs_template,
        }

        self._log("task_received", self._task_payload(task))

        with self.tracer.start_as_current_span("multi_agent_run_task") as root_span:
            root_span.set_attribute("task.id", task.task_id)
            root_span.set_attribute("task.multi_agent", True)

            # === Шаг 1: Проверка доверия ===
            with self.tracer.start_as_current_span("trust_check") as trust_span:
                trust_decision = self.trust_manager.can_modify(task)
                self._log("trust_decision", _to_dict(trust_decision))
                trust_span.set_attribute("trust.allowed", trust_decision.allowed)

            if not trust_decision.allowed:
                root_span.set_attribute("task.approved", False)
                root_span.set_attribute("task.rejected_reason", "trust")
                return self._deny(
                    task=task,
                    stage="trust",
                    reason=trust_decision.reason,
                )

            # === Шаг 2: Генерация кода (GeneratorAgent) ===
            with self.tracer.start_as_current_span("generator_agent") as gen_span:
                gen_result = self.generator_agent.run(task, context)
                self._log("generator_agent", self._agent_result_payload(gen_result))
                gen_span.set_attribute("agent.success", gen_result.success)

            if not gen_result.success:
                root_span.set_attribute("task.approved", False)
                root_span.set_attribute("task.rejected_reason", "generator_agent")
                return EvaluationResult(
                    task_id=task.task_id,
                    approved=False,
                    details={
                        "stage": "generator_agent",
                        "reason": gen_result.error or "Generation failed",
                    },
                )

            context["new_code"] = gen_result.output["new_code"]
            context["rationale"] = gen_result.output["rationale"]

            # === Шаг 3: Анализ безопасности (SecurityAgent) ===
            with self.tracer.start_as_current_span("security_agent") as sec_span:
                sec_result = self.security_agent.run(task, context)
                self._log("security_agent", self._agent_result_payload(sec_result))
                sec_span.set_attribute("agent.success", sec_result.success)

            if not sec_result.success:
                root_span.set_attribute("task.approved", False)
                root_span.set_attribute("task.rejected_reason", "security_agent")
                return EvaluationResult(
                    task_id=task.task_id,
                    approved=False,
                    details={
                        "stage": "security_agent",
                        "reason": sec_result.error or "Security analysis failed",
                    },
                )

            if not sec_result.output.get("approved", False):
                reason = "security_violation"
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
                root_span.set_attribute("task.rejected_reason", "security_violation")
                return EvaluationResult(
                    task_id=task.task_id,
                    approved=False,
                    safety_score=0.0,
                    details={
                        "stage": "security_agent",
                        "vulnerabilities": sec_result.output.get("vulnerabilities", []),
                        "warnings": sec_result.output.get("warnings", []),
                    },
                )

            # === Шаг 4: Генерация тестов (TestAgent) ===
            with self.tracer.start_as_current_span("test_agent") as test_span:
                test_result = self.test_agent.run(task, context)
                self._log("test_agent", self._agent_result_payload(test_result))
                test_span.set_attribute("agent.success", test_result.success)

            if test_result.success and test_result.output.get("tests"):
                generated_tests = test_result.output["tests"]

                # Добавляем сгенерированные тесты к существующим
                if test_suite:
                    test_suite = test_suite + generated_tests
                elif test_code:
                    test_suite = [test_code] + generated_tests
                else:
                    test_suite = generated_tests

                context["test_suite"] = test_suite

            # === Шаг 5: Рефакторинг (RefactorAgent) ===
            with self.tracer.start_as_current_span("refactor_agent") as refactor_span:
                refactor_result = self.refactor_agent.run(task, context)
                self._log("refactor_agent", self._agent_result_payload(refactor_result))
                refactor_span.set_attribute("agent.success", refactor_result.success)

            if refactor_result.success:
                context["new_code"] = refactor_result.output["refactored_code"]

            # === Шаг 6: Проверка через Constitutional AI Layer ===
            with self.tracer.start_as_current_span("constitutional_check") as safety_span:
                safety_result = self.safety_guard.check(context["new_code"])
                self._log("safety_check", _to_dict(safety_result))
                safety_span.set_attribute("safety.approved", safety_result.approved)

            if not safety_result.approved:
                reason = "constitutional_ai_violation"
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
                root_span.set_attribute("task.rejected_reason", "constitutional_ai")
                return EvaluationResult(
                    task_id=task.task_id,
                    approved=False,
                    safety_score=0.0,
                    details={
                        "stage": "constitutional_ai",
                        "violations": list(safety_result.violations),
                        "warnings": list(safety_result.warnings),
                    },
                )

            # === Шаг 7: Выполнение в Sandbox ===
            combined_test_code = "\n".join(test_suite) if test_suite else test_code

            with self.tracer.start_as_current_span("sandbox_execution") as sandbox_span:
                execution_result = self.sandbox_executor.run(
                    context["new_code"],
                    combined_test_code,
                )
                self._log("sandbox_execution", _to_dict(execution_result))
                sandbox_span.set_attribute("sandbox.success", execution_result.success)

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
                root_span.set_attribute("task.approved", False)
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

            # === Шаг 8: Оценка результата ===
            from ..models import ChangeProposal

            proposal = ChangeProposal(
                task_id=task.task_id,
                new_code=context["new_code"],
                rationale=context.get("rationale", ""),
                model_name=gen_result.output.get("model_name", "unknown"),
            )

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
                self._log("evaluation_result", _to_dict(evaluation_result))
                eval_span.set_attribute("evaluation.approved", evaluation_result.approved)
                if evaluation_result.overall_efficiency_score is not None:
                    eval_span.set_attribute(
                        "evaluation.overall_efficiency_score",
                        evaluation_result.overall_efficiency_score,
                    )

            if evaluation_result.approved:
                self.trust_manager.record_success(task)
                self._log(
                    "trust_updated_after_success",
                    {
                        "task_id": task.task_id,
                        "level": self.trust_manager.level.name,
                    },
                )
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

            root_span.set_attribute("task.approved", evaluation_result.approved)

            return evaluation_result

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

    @staticmethod
    def _agent_result_payload(result: AgentResult) -> dict[str, Any]:
        return {
            "agent_name": result.agent_name,
            "success": result.success,
            "duration_sec": result.duration_sec,
            "error": result.error,
            "output_keys": list(result.output.keys()) if result.output else [],
        }
