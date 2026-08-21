from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class PolicyRule:
    """Single policy rule."""
    name: str
    condition: str
    action: str  # "block", "approve", "require_human", "warning"
    risk_score_delta: int = 0
    description: str = ""


@dataclass
class Policy:
    """Policy definition."""
    name: str
    description: str
    rules: list[PolicyRule] = field(default_factory=list)
    applies_to: list[str] = field(default_factory=list)  # agent_ids or "*"
    priority: int = 0


@dataclass
class RiskAssessment:
    """Risk assessment result."""
    risk_score: int  # 0-100
    risk_level: str  # "low", "medium", "high", "critical"
    matched_rules: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    requires_human_review: bool = False
    recommendation: str = "approve"  # "approve", "block", "review"


class PolicyEngine:
    """
    Policy engine for AI code change verification.

    Evaluates code changes against YAML-defined policies and calculates risk scores.
    """

    def __init__(self, policies_dir: str = "policies"):
        self.policies_dir = Path(policies_dir)
        self.policies_dir.mkdir(parents=True, exist_ok=True)
        self.policies: list[Policy] = []
        self._load_policies()

    def _load_policies(self) -> None:
        """Load all policies from YAML files."""
        self.policies = []

        for policy_file in self.policies_dir.glob("*.yaml"):
            try:
                with open(policy_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not data:
                    continue

                policy = Policy(
                    name=data.get("name", policy_file.stem),
                    description=data.get("description", ""),
                    applies_to=data.get("applies_to", ["*"]),
                    priority=data.get("priority", 0),
                )

                for rule_data in data.get("rules", []):
                    rule = PolicyRule(
                        name=rule_data.get("name", "unnamed"),
                        condition=rule_data.get("condition", ""),
                        action=rule_data.get("action", "warning"),
                        risk_score_delta=rule_data.get("risk_score_delta", 0),
                        description=rule_data.get("description", ""),
                    )
                    policy.rules.append(rule)

                self.policies.append(policy)
            except Exception as exc:
                print(f"Warning: Failed to load policy {policy_file}: {exc}")

        # Sort by priority (highest first)
        self.policies.sort(key=lambda p: p.priority, reverse=True)

    def _evaluate_condition(
        self,
        condition: str,
        context: dict[str, Any],
    ) -> bool:
        """
        Evaluate a policy condition against context.

        Supported conditions:
        - "proposed_code contains 'os.system'"
        - "proposed_code matches 'import\\s+os'"
        - "target_path ends_with '.py'"
        - "current_code_length > 1000"
        - "agent_id starts_with 'agent-prod'"
        """
        try:
            # Parse condition
            parts = condition.split()

            if len(parts) < 3:
                return False

            field_name = parts[0]
            operator = parts[1]
            value = " ".join(parts[2:]).strip("'\"")

            # Get field value from context
            field_value = context.get(field_name)

            if field_value is None:
                return False

            # Convert to string for comparison
            field_value_str = str(field_value)

            # Evaluate based on operator
            if operator == "contains":
                return value in field_value_str

            elif operator == "not_contains":
                return value not in field_value_str

            elif operator == "matches":
                return bool(re.search(value, field_value_str))

            elif operator == "starts_with":
                return field_value_str.startswith(value)

            elif operator == "ends_with":
                return field_value_str.endswith(value)

            elif operator == "equals":
                return field_value_str == value

            elif operator in (">", "<", ">=", "<=", "=="):
                try:
                    num_field = float(field_value_str)
                    num_value = float(value)

                    if operator == ">":
                        return num_field > num_value
                    elif operator == "<":
                        return num_field < num_value
                    elif operator == ">=":
                        return num_field >= num_value
                    elif operator == "<=":
                        return num_field <= num_value
                    elif operator == "==":
                        return num_field == num_value
                except ValueError:
                    return False

            return False

        except Exception:
            return False

    def assess_risk(
        self,
        agent_id: str,
        target_path: str,
        current_code: str,
        proposed_code: str,
    ) -> RiskAssessment:
        """
        Assess risk for a code change.

        Args:
            agent_id: Agent identifier
            target_path: Target file path
            current_code: Current version of code
            proposed_code: Proposed new code

        Returns:
            RiskAssessment with score and matched rules
        """
        # Build context
        context = {
            "agent_id": agent_id,
            "target_path": target_path,
            "current_code": current_code,
            "proposed_code": proposed_code,
            "current_code_length": len(current_code),
            "proposed_code_length": len(proposed_code),
            "code_diff_length": abs(len(proposed_code) - len(current_code)),
        }

        # Find applicable policies
        applicable_policies = [
            p for p in self.policies
            if "*" in p.applies_to or agent_id in p.applies_to
        ]

        # Evaluate rules
        risk_score = 0
        matched_rules = []
        warnings = []
        requires_human = False
        recommendation = "approve"

        for policy in applicable_policies:
            for rule in policy.rules:
                if self._evaluate_condition(rule.condition, context):
                    matched_rules.append(f"{policy.name}:{rule.name}")

                    # Apply action
                    if rule.action == "block":
                        recommendation = "block"
                        risk_score += rule.risk_score_delta

                    elif rule.action == "require_human":
                        requires_human = True
                        recommendation = "review"
                        risk_score += rule.risk_score_delta

                    elif rule.action == "warning":
                        warnings.append(f"{policy.name}:{rule.name} - {rule.description}")
                        risk_score += rule.risk_score_delta

                    elif rule.action == "approve":
                        risk_score += rule.risk_score_delta

        # Clamp risk score to 0-100
        risk_score = max(0, min(100, risk_score))

        # Determine risk level
        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Override recommendation based on risk level
        if risk_level == "critical":
            recommendation = "block"
        elif risk_level == "high":
            recommendation = "review"

        return RiskAssessment(
            risk_score=risk_score,
            risk_level=risk_level,
            matched_rules=matched_rules,
            warnings=warnings,
            requires_human_review=requires_human,
            recommendation=recommendation,
        )

    def list_policies(self) -> list[dict[str, Any]]:
        """List all loaded policies."""
        return [
            {
                "name": p.name,
                "description": p.description,
                "applies_to": p.applies_to,
                "priority": p.priority,
                "rules_count": len(p.rules),
            }
            for p in self.policies
        ]
