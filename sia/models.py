from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional


class TrustLevel(IntEnum):
    NOVICE = 0
    INTERN = 1
    JUNIOR = 2
    MID = 3
    SENIOR = 4


@dataclass(frozen=True)
class Task:
    description: str
    target_path: str
    current_code: str
    target_symbol: Optional[str] = None
    allowed_paths: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass(frozen=True)
class ChangeProposal:
    task_id: str
    new_code: str
    rationale: str = ""
    model_name: str = ""
    raw_response: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TrustDecision:
    allowed: bool
    current_level: TrustLevel
    reason: str


@dataclass(frozen=True)
class SafetyCheckResult:
    approved: bool
    violations: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    duration_sec: float = 0.0
    timed_out: bool = False
    container_id: Optional[str] = None
    error: Optional[str] = None
    artifacts: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationResult:
    task_id: str
    approved: bool
    performance_gain: Optional[float] = None
    safety_score: Optional[float] = None
    benchmark_pass_rate: Optional[float] = None
    semantic_equivalence: Optional[bool] = None
    semantic_test_results: Optional[dict[str, Any]] = None
    quality_score: Optional[float] = None
    security_vulnerabilities: Optional[int] = None
    overall_efficiency_score: Optional[float] = None
    old_cost_usd: Optional[float] = None
    new_cost_usd: Optional[float] = None
    cost_savings_usd: Optional[float] = None
    cost_reduction: Optional[float] = None
    test_results: Optional[dict[str, Any]] = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EquivalenceReport:
    """Отчёт о семантической эквивалентности с доверительным интервалом.

    `ci_lower`/`ci_upper` — интервал Вильсона для доли проходов новой
    версии на тестовом сьюте при заданном уровне доверия.
    """

    total: int
    passed_old: int
    passed_new: int
    failed_old: tuple[str, ...] = ()
    failed_new: tuple[str, ...] = ()
    new_only_failures: tuple[str, ...] = ()
    pass_rate_old: float = 0.0
    pass_rate_new: float = 0.0
    ci_lower: float = 0.0
    ci_upper: float = 1.0
    confidence_level: float = 0.95
    repetitions: int = 1

    @property
    def equivalent(self) -> bool:
        return self.total > 0 and not self.failed_old and not self.failed_new

    @property
    def verdict(self) -> str:
        if self.total == 0:
            return "inconclusive"
        if self.failed_old or self.failed_new:
            return "degraded"
        return "equivalent"

    def to_dict(self) -> dict[str, Any]:
        return {
            "equivalent": self.equivalent,
            "total": self.total,
            "passed_old": self.passed_old,
            "passed_new": self.passed_new,
            "failed_old": list(self.failed_old),
            "failed_new": list(self.failed_new),
            "new_only_failures": list(self.new_only_failures),
            "pass_rate_old": self.pass_rate_old,
            "pass_rate_new": self.pass_rate_new,
            "ci_lower": self.ci_lower,
            "ci_upper": self.ci_upper,
            "confidence_level": self.confidence_level,
            "repetitions": self.repetitions,
            "verdict": self.verdict,
        }
